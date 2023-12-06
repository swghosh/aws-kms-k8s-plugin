/*
Copyright 2020 The Kubernetes Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	pb "k8s.io/kms/apis/v2"
	"sigs.k8s.io/aws-encryption-provider/pkg/kmsplugin"
	"sigs.k8s.io/aws-encryption-provider/pkg/tpm"
)

var _ pb.KeyManagementServiceServer = &V2Plugin{}

const (
	GRPC_V2 = "v2"
)

// Plugin implements the KeyManagementServiceServer
type V2Plugin struct {
	svc           kmsiface.KMSAPI
	keyID         string
	encryptionCtx map[string]*string
	healthCheck   *SharedHealthCheck
	keyCache      map[string]bool
	localCrypto   *tpm.LocalCryptoEngine
}

// New returns a new *V2Plugin
func NewV2(key string, svc kmsiface.KMSAPI, encryptionCtx map[string]string, healthCheck *SharedHealthCheck, tpmSealer *tpm.TPMSealer) *V2Plugin {
	return newPluginV2(
		key,
		svc,
		encryptionCtx,
		healthCheck,
		tpmSealer,
	)
}

func newPluginV2(
	key string,
	svc kmsiface.KMSAPI,
	encryptionCtx map[string]string,
	healthCheck *SharedHealthCheck,
	tpmSealer *tpm.TPMSealer,
) *V2Plugin {
	p := &V2Plugin{
		svc:         svc,
		keyID:       key,
		healthCheck: healthCheck,
		keyCache:    make(map[string]bool),
		localCrypto: tpm.NewLocalCryptoEngine(tpmSealer, 10),
	}
	if len(encryptionCtx) > 0 {
		p.encryptionCtx = make(map[string]*string)
	}
	for k, v := range encryptionCtx {
		p.encryptionCtx[k] = aws.String(v)
	}
	return p
}

// Health checks KMS API availability.
//
// The goal is to:
//  1. not incur extra KMS API call if V2Plugin "Encrypt" method has already
//  2. return latest health status (cached KMS status must reflect the current)
//
// The error is sent via channel and consumed by goroutine.
// The error channel may be full and block, when there are too many failures.
// The error channel may be empty and block, when there's no failure.
// To handle those two cases, keep track latest health check timestamps.
//
// Call KMS "Encrypt" API call iff:
//  1. there was never a health check done
//  2. there was no health check done for the last "healthCheckPeriod"
//     (only use the cached error if the error is from recent API call)
func (p *V2Plugin) Health() error {
	// recent, err := p.healthCheck.isRecentlyChecked()
	// if !recent {
	// 	_, err = p.Encrypt(context.Background(), &pb.EncryptRequest{Plaintext: []byte("foo")})
	// 	p.healthCheck.recordErr(err)
	// 	if err != nil {
	// 		zap.L().Warn("health check failed", zap.Error(err))
	// 	}
	// 	return err
	// }
	// if err != nil {
	// 	zap.L().Warn("cached health check failed", zap.Error(err))
	// } else {
	// 	zap.L().Debug("health check success")
	// }
	// return err
	return nil
}

func (p *V2Plugin) Live() error {
	if err := p.Health(); err != nil && kmsplugin.ParseError(err) != kmsplugin.KMSErrorTypeUserInduced {
		return err
	}
	return nil
}

// Status returns the V2Plugin server status
func (p *V2Plugin) Status(ctx context.Context, request *pb.StatusRequest) (*pb.StatusResponse, error) {
	status := "ok"
	if p.Health() != nil {
		status = "err"
	}
	return &pb.StatusResponse{
		Version: "v2beta1",
		Healthz: status,
		KeyId:   p.keyID,
	}, nil
}

// Encrypt executes the encryption operation using AWS KMS
func (p *V2Plugin) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	zap.L().Debug("starting encrypt operation")

	zap.L().Debug("##1: plugin has been requested to encrypt: '" + string(request.Plaintext[:]) + "'")
	p.keyCache[string(request.Plaintext[:])] = true
	zap.L().Debug(fmt.Sprintf("###: Number of keys in plugin cache: %d", len(p.keyCache)))

	startTime := time.Now()
	input := &kms.EncryptInput{
		Plaintext: request.Plaintext,
		KeyId:     aws.String(p.keyID),
	}
	if len(p.encryptionCtx) > 0 {
		zap.L().Debug("configuring encryption context", zap.String("ctx", fmt.Sprintf("%v", p.encryptionCtx)))
		input.EncryptionContext = p.encryptionCtx
	}

	result, err := p.svc.Encrypt(input)
	if err != nil {
		select {
		case p.healthCheck.healthCheckErrc <- err:
		default:
		}
		zap.L().Error("request to encrypt failed", zap.String("error-type", kmsplugin.ParseError(err).String()), zap.Error(err))
		failLabel := kmsplugin.GetStatusLabel(err)
		kmsLatencyMetric.WithLabelValues(p.keyID, failLabel, kmsplugin.OperationEncrypt, GRPC_V2).Observe(kmsplugin.GetMillisecondsSince(startTime))
		kmsOperationCounter.WithLabelValues(p.keyID, failLabel, kmsplugin.OperationEncrypt, GRPC_V2).Inc()
		return nil, fmt.Errorf("failed to encrypt %w", err)
	}

	// res, err := EncryptWithTPM(ctx, request)
	// if err != nil {
	// 	return nil, err
	// }
	// concat res.Text together

	localCipher, err := p.localCrypto.Encrypt(string(request.Plaintext))
	if err != nil {
		return nil, err
	}
	mergedCipher := tpm.WrapCipher(result.CiphertextBlob, localCipher)

	zap.L().Debug("encrypt operation successful")
	kmsLatencyMetric.WithLabelValues(p.keyID, kmsplugin.StatusSuccess, kmsplugin.OperationEncrypt, GRPC_V2).Observe(kmsplugin.GetMillisecondsSince(startTime))
	kmsOperationCounter.WithLabelValues(p.keyID, kmsplugin.StatusSuccess, kmsplugin.OperationEncrypt, GRPC_V2).Inc()

	zap.L().Debug("##2: plugin encrypted plaintext DEK to: '" + fmt.Sprintf("0x%x", result.CiphertextBlob) + "'")

	return &pb.EncryptResponse{
		Ciphertext: mergedCipher,
		KeyId:      p.keyID,
	}, nil
}

// Decrypt executes the decrypt operation using AWS KMS
func (p *V2Plugin) Decrypt(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	zap.L().Debug("starting decrypt operation")

	zap.L().Debug("##3: plugin has been requested to decrypt: '" + fmt.Sprintf("0x%x", request.Ciphertext) + "'")

	mergedCipher, err := tpm.UnwrapCipher(request.Ciphertext)
	if err != nil {
		return nil, err
	}

	startTime := time.Now()
	input := &kms.DecryptInput{
		CiphertextBlob: mergedCipher.Kmsenc,
	}
	if len(p.encryptionCtx) > 0 {
		zap.L().Debug("configuring encryption context", zap.String("ctx", fmt.Sprintf("%v", p.encryptionCtx)))
		input.EncryptionContext = p.encryptionCtx
	}

	result, err := p.svc.Decrypt(input)
	if err != nil {

		// res, err := DecryptFromTPM(ctx, request)
		// if err != nil {
		// 	zap.L().Info("tpm error")
		// } else {
		// 	return res, nil
		// }

		dek, err := p.localCrypto.Decrypt(string(mergedCipher.Tpmenc))
		if err == nil {
			return &pb.DecryptResponse{Plaintext: []byte(dek)}, nil
		} else {
			zap.L().Info("tpm error had occured")
		}

		select {
		case p.healthCheck.healthCheckErrc <- err:
		default:
		}
		zap.L().Error("request to decrypt failed", zap.String("error-type", kmsplugin.ParseError(err).String()), zap.Error(err))
		failLabel := kmsplugin.GetStatusLabel(err)
		kmsLatencyMetric.WithLabelValues(p.keyID, failLabel, kmsplugin.OperationDecrypt, GRPC_V2).Observe(kmsplugin.GetMillisecondsSince(startTime))
		kmsOperationCounter.WithLabelValues(p.keyID, failLabel, kmsplugin.OperationDecrypt, GRPC_V2).Inc()
		return nil, fmt.Errorf("failed to decrypt %w", err)
	}

	zap.L().Debug("decrypt operation successful")
	kmsLatencyMetric.WithLabelValues(p.keyID, kmsplugin.StatusSuccess, kmsplugin.OperationDecrypt, GRPC_V2).Observe(kmsplugin.GetMillisecondsSince(startTime))
	kmsOperationCounter.WithLabelValues(p.keyID, kmsplugin.StatusSuccess, kmsplugin.OperationDecrypt, GRPC_V2).Inc()

	p.keyCache[string(result.Plaintext[:])] = true
	zap.L().Debug(fmt.Sprintf("###: Number of keys in plugin cache: %d", len(p.keyCache)))
	zap.L().Debug("##4: plugin decrypted encrypted DEK to: '" + string(result.Plaintext[:]) + "'")

	return &pb.DecryptResponse{Plaintext: result.Plaintext}, nil
}

// Register registers the V2Plugin with the grpc server
func (p *V2Plugin) Register(s *grpc.Server) {
	zap.L().Info("registering the kmsplugin plugin with grpc server")
	pb.RegisterKeyManagementServiceServer(s, p)
}
