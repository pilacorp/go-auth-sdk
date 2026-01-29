## Go Auth SDK

Go **Auth SDK** chuẩn hóa **Authentication + Authorization** dựa trên **Verifiable Credentials (VC)** (VC-JWT), giúp các service trong hệ sinh thái dùng chung một mô hình bảo mật nhất quán.

### Tính năng chính (Features)

- **Policy-based permissions**: phân quyền chi tiết theo action/resource/condition, không còn kiểu “all-or-nothing”.
- **Flow VC-JWT end-to-end**: build credential, sign, verify, extract permissions.
- **Pluggable signer**: ký bằng private key local hoặc Vault signer.
- **Tích hợp status (revocation)**: hỗ trợ `credentialStatus` để check thu hồi credential.

### Cài đặt (Installation)

```bash
go get github.com/pilacorp/go-auth-sdk
```

### Sử dụng nhanh (Quick Start / Usage)

#### 1. Flow tổng quan

- **Issuer**: build 1 Authorization Credential (VC-JWT) chứa:
  - issuer DID, holder DID
  - schema ID
  - thời gian hiệu lực (validFrom, validUntil)
  - danh sách permissions (policy)
  - credentialStatus (revocation)
- **Ký credential**: dùng `signer.Signer` (ECDSA hoặc Vault) → ra VC-JWT.
- **Holder**: gọi API với header `Authorization: Bearer <vc-jwt>`.
- **Service**: dùng `auth.Verify` để:
  - verify chữ ký, thời gian, schema, revocation (tùy option)
  - trích xuất issuer DID, holder DID, permissions đã chuẩn hóa.

#### 2. Cấu trúc input khi build: `AuthData`

```go
type AuthData struct {
	ID               string        // optional: ID của credential, nếu trống SDK sẽ tự sinh UUID
	IssuerDID        string        // bắt buộc: DID của Issuer (người ký credential)
	SchemaID         string        // optional: ID schema; nếu trống sẽ dùng DefaultSchemaID
	HolderDID        string        // bắt buộc: DID của Holder (credentialSubject.id)
	Policy           policy.Policy // bắt buộc: danh sách permissions
	ValidFrom        *time.Time    // optional: thời điểm credential bắt đầu có hiệu lực
	ValidUntil       *time.Time    // optional: thời điểm credential hết hiệu lực
	CredentialStatus []vc.Status   // bắt buộc: thông tin status (revocation) để hỗ trợ kiểm tra thu hồi
}
```

- **IssuerDID**: DID của hệ thống phát hành credential (ví dụ: DID của Issuer service).
- **HolderDID**: DID của user/subject sẽ cầm credential.
- **SchemaID**:
  - Dùng để validate cấu trúc credential phía verifier.
  - Nếu không truyền, SDK dùng hằng `DefaultSchemaID` đã được cấu hình sẵn:

```go
const DefaultSchemaID = "https://auth-dev.pila.vn/api/v1/schemas/e8429e35-5486-4f05-a06c-2bd211f99fc8"
```

- **Policy**: danh sách statement mô tả quyền:

```go
stmt := policy.NewStatement(
	policy.EffectAllow,                              // "allow" hoặc "deny"
	[]policy.Action{policy.NewAction("Credential:Create")}, // actions
	[]policy.Resource{policy.NewResource(policy.ResourceObjectCredential)}, // resources
	policy.NewCondition(),                           // conditions (có thể rỗng)
)

p := policy.NewPolicy(
	policy.WithStatements(stmt),
)
```

- **CredentialStatus** (bắt buộc):
  - Dùng để gắn thông tin status cho credential (đặc biệt để check revocation).
  - Kiểu dữ liệu `[]vc.Status`.
  - Mỗi lần build credential mới, Issuer cần có **ít nhất một status entry** tương ứng trên status service, sau đó gán vào trường này.
  - Có 2 cách chính:
    - **Dùng helper `StatusBuilder` của SDK**: gọi API status registry và map về `[]vc.Status`.
    - **Tự tạo struct `vc.Status`**: nếu bạn đã có sẵn thông tin status, chỉ cần khởi tạo theo mẫu dưới đây và gán vào `CredentialStatus`.

Ví dụ 1 phần tử status:

```json
{
  "id": "did:.../credentials/status/0#0",
  "statusListCredential": "https://.../credentials/status/0",
  "statusListIndex": "0",
  "statusPurpose": "revocation",
  "type": "BitstringStatusListEntry"
}
```

#### 3. Signer (ký credential)

SDK hỗ trợ 2 loại signer để ký credential:

##### 3.1. ECDSA Signer (local private key)

ECDSA signer dùng private key local để ký. Có 2 cách khởi tạo:

**Cách 1: Khởi tạo không có key, truyền key qua options khi sign**

```go
import "github.com/pilacorp/go-auth-sdk/signer/ecdsa"

ecdsaSigner := ecdsa.NewPrivSigner()
// Private key phải được truyền qua signer.WithPrivateKey() khi gọi Build()
resp, err := auth.Build(ctx, data, ecdsaSigner, signer.WithPrivateKey(myPrivKeyBytes))
```

**Cách 2: Khởi tạo với key trong struct**

```go
import "github.com/pilacorp/go-auth-sdk/signer/ecdsa"

ecdsaSigner := ecdsa.NewPrivSignerWithPrivateKey(myPrivKeyBytes)
// Có thể dùng key trong struct, hoặc override bằng signer.WithPrivateKey()
resp, err := auth.Build(ctx, data, ecdsaSigner) // dùng key trong struct
// hoặc
resp, err := auth.Build(ctx, data, ecdsaSigner, signer.WithPrivateKey(anotherKey)) // override bằng key khác
```

**Priority của private key:**
- Nếu truyền `signer.WithPrivateKey()` trong options → dùng key từ options (priority cao nhất)
- Nếu không có trong options → dùng key từ struct (nếu có)
- Nếu cả 2 đều không có → trả về lỗi

##### 3.2. Vault Signer (remote signing service)

Vault signer ký credential thông qua Vault service (phù hợp cho production, key không lưu local):

```go
import "github.com/pilacorp/go-auth-sdk/signer/vault"

vaultSigner := vault.NewVaultSigner("https://vault.example.com", "vault-token")
// Signer address phải được truyền qua signer.WithSignerAddress() khi gọi Build()
resp, err := auth.Build(ctx, data, vaultSigner, signer.WithSignerAddress("0x1234..."))
```

**Lưu ý:**
- Vault signer yêu cầu `signer.WithSignerAddress()` để chỉ định địa chỉ account trong Vault
- Nếu không truyền signer address → sẽ trả về lỗi

#### 4. Build credential (tạo VC-JWT)

```go
ctx := context.Background()

// 1) Nếu dùng StatusBuilder để tạo status tự động:
statusBuilder := auth.NewDefaultStatusBuilder("Bearer <issuer-access-token>")

statuses, err := statusBuilder.CreateStatus(ctx, "did:nda:testnet:0xISSUER")
if err != nil {
	log.Fatalf("create status error: %v", err)
}

// 2) Hoặc tự tạo vc.Status thủ công (khi đã có sẵn thông tin từ status service):
// statuses := []vc.Status{
// 	{
// 		ID:                   "did:.../credentials/status/0#0",
// 		Type:                 "BitstringStatusListEntry",
// 		StatusPurpose:        "revocation",
// 		StatusListIndex:      "0",
// 		StatusListCredential: "https://.../credentials/status/0",
// 	},
// }

data := auth.AuthData{
	IssuerDID: "did:nda:testnet:0xISSUER",
	HolderDID: "did:nda:testnet:0xHOLDER",
	Policy:    p,                 // policy.Policy từ ví dụ trên
	CredentialStatus: statuses,   // bắt buộc: status cho credential này
	// SchemaID: để trống để dùng DefaultSchemaID
	// ValidFrom / ValidUntil: có thể set nếu cần
}

// signer: có thể là ECDSA signer hoặc Vault signer (xem section 3 ở trên)
ecdsaSigner := ecdsa.NewPrivSigner()

resp, err := auth.Build(ctx, data, ecdsaSigner, signer.WithPrivateKey(myPrivKeyBytes))
if err != nil {
	log.Fatalf("build credential error: %v", err)
}

// resp.Token là VC-JWT (dạng string JSON/JWT) mà bạn trả về cho client/holder.
fmt.Println("VC-JWT:", resp.Token)
```

#### 5. Verify credential (check VC-JWT + extract permissions)

```go
ctx := context.Background()

result, err := auth.Verify(
	ctx,
	[]byte(resp.Token),
	auth.WithVerifyProof(),                  // bật verify chữ ký
	auth.WithCheckExpiration(),              // kiểm tra thời gian hiệu lực
	auth.WithSchemaValidation(),             // validate theo schema
	auth.WithCheckRevocation(),              // (optional) kiểm tra status/revocation
	auth.WithSchemaID(auth.DefaultSchemaID), // kỳ vọng đúng schema ID
	auth.WithDIDBaseURL("https://api.ndadid.vn/api/v1/did"), // URL để resolve DID document
)
if err != nil {
	log.Fatalf("verify credential error: %v", err)
}

fmt.Println("Issuer DID:", result.IssuerDID)
fmt.Println("Holder DID:", result.HolderDID)
fmt.Printf("Permissions: %+v\n", result.Permissions)
```

### Repo structure

- `auth/`: API chính cho build/verify VC-JWT.
- `auth/policy/`: Kiểu dữ liệu policy/permission và hàm validate.
- `signer/`: `Signer` interface + implement ECDSA signer, Vault signer.
- `examples/`: Các ví dụ sử dụng SDK.

