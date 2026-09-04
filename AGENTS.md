# AGENTS.md

Đọc file này trước khi sửa code BeeBox. README là ý tưởng. `docs/PRODUCT.md` là flow người dùng. File này là luật khi implement.

Nếu code, comment, hoặc PR mâu thuẫn với file này — file này thắng. Muốn đổi quyết định thì sửa document trước, rồi mới sửa code.

## Sản phẩm

BeeBox là BaaS. Chủ project cấu hình backend trên dashboard, nhận URL + key, chỉ viết frontend.

Hai plane:

- **control** — chủ project: project, plan, module, field, key, origin, danh sách user.
- **runtime** — frontend/app khách: auth, me, data, file, realtime.

Không viết tính năng runtime vào control và ngược lại.

Hai loại user không được trộn bảng:

- tài khoản BeeBox (chủ project)
- `app_users` (user cuối, luôn có `project_id`)

## Việc không làm

- Microservice theo màn hình: `beebox-module-signin`, `beebox-module-signup`, `beebox-plans` riêng process.
- `CREATE SCHEMA` / `CREATE DATABASE` mỗi project.
- Table vật lý `products_quan_a`. Collection động → metadata + `records` (+ JSONB).
- JWT dài hạn không revoke được, không có session store.
- Nhận `isVerified`, `isAdmin`, `role=admin` từ body client.
- Bỏ secret key vào example frontend.
- Log raw password, OTP, secret key, header `Authorization`.
- Unique email/phone global. Unique phải theo `(project_id, email)`.
- Plan chặn theo tên field (`fullName` vs `firstName`). Plan chặn số lượng, type, module.
- OAuth coi như một field user.
- Clean Architecture biến thành 15 interface cho một CRUD lúc chưa có test.

## Việc phải làm

- Shared Postgres + `project_id` trên mọi bảng tenant.
- Bật RLS khi đụng bảng tenant. Request runtime `SET LOCAL app.current_project`.
- Module = plugin in-process, đăng ký tên + plan tối thiểu + route.
- `auth.password` gồm sign-up, sign-in, reset, change password.
- Identifier (email/phone) tách field tùy chọn.
- Password: argon2id. So sánh constant-time.
- Session: opaque id (Redis hoặc bảng sessions) + cookie httpOnly hoặc access token ngắn.
- Key: prefix `pk_test_` `pk_live_` `sk_test_` `sk_live_`. Lưu hash secret. Show secret một lần.
- Public key chỉ làm được việc public. Mọi admin đi secret key.
- Runtime browser: check Origin allowlist.
- Rate limit theo IP + project + key + identifier.
- `/v1/client/config` public (có `pk_`): trả module enabled + field defs, không trả secret, không trả private metadata.
- Validate body theo `user_field_defs` / `collection_fields` của project, không theo struct Go cứng cho `FullName`.

## Cấu trúc mục tiêu

```text
cmd/control/
cmd/runtime/
cmd/worker/
internal/project/
internal/billing/      plan, quota, usage
internal/iam/          keys, origin, session actor
internal/schema/       field registry, validate
internal/module/
  registry.go
  auth/
  data/
  file/
  realtime/
internal/platform/     postgres, redis, http, log
```

Một Go module. Một hoặc hai process lúc đầu. Worker khi có mail/SMS.

Được phép tách sau: control, runtime, worker, realtime. Không tách plans hay signin.

## Multi-tenant

Mọi query tenant phải có `project_id`.

Resolve project từ:

1. Host slug (`quan-tra-dao.api.beebox.dev`)
2. hoặc path `/p/{projectId}`
3. rồi xác thực `pk_` / `sk_` thuộc project đó

Không tin `project_id` client gửi trong body.

Test và live là hai instance/data path. `pk_test_` không đụng data live.

## Plan và module

```text
projects.plan_id
project_modules(project_id, module_name)
plans.limits JSON
```

Trước handler runtime:

1. project active?
2. module enabled?
3. còn quota?

Thiếu quyền: lỗi rõ (`module_disabled`, `plan_limit_fields`), không phải 500.

Thêm module mới = package mới trong `internal/module` + `module.Register(...)`, không tạo repo/service.

## Schema động

Không generate struct per project.

- Định nghĩa field lưu DB
- Record user custom attrs: JSONB
- Record collection: bảng `records(project_id, collection_id, owner_user_id, data jsonb)`

Validate type, required, unique theo definition. Index GIN / biểu thức chỉ khi có nhu cầu filter thật.

## HTTP

Runtime prefix `/v1`.

Auth (khi module bật):

```text
POST /v1/auth/sign-up
POST /v1/auth/sign-in
POST /v1/auth/sign-out
GET  /v1/auth/me
```

Config:

```text
GET /v1/client/config
```

Data (sau này):

```text
GET    /v1/data/{collection}
POST   /v1/data/{collection}
GET    /v1/data/{collection}/{id}
PATCH  /v1/data/{collection}/{id}
DELETE /v1/data/{collection}/{id}
```

JSON lỗi:

```json
{ "error": { "code": "plan_limit_fields", "message": "..." } }
```

Không trả stack trace ra client.

## Bảo mật tối thiểu

- CORS theo allowlist, không `*` khi dùng cookie.
- CSRF nếu session cookie.
- OTP: TTL, max attempt, one-time, không log mã.
- Refresh rotation nếu có refresh token.
- Audit: login fail, đổi schema, tạo/revoke key. Lưu `key_id`, không lưu raw key.

## Style code

- Go idiomatic. Context đi xuyên request.
- Tên module/file theo bounded context, không theo page UI.
- Comment giải thích quyết định, không diễn giải lại tên hàm.
- Không thêm framework nếu std + một router đủ.
- Migration SQL có version. Không sửa tay production schema.
- Test: tenant isolation, plan limit, public key không gọi được admin.

## Khi được nhờ “thêm service mới”

Mặc định từ chối nếu đó là module auth/data hoặc bảng plans.

Chỉ đồng ý tách process khi có lý do: scale độc lập, hàng đợi, bảo mật key signing, team riêng.

## Khi được nhờ “mỗi project một DB”

Từ chối mặc định. Nhắc shared schema + RLS. Tách DB chỉ khi có khách enterprise và router theo `project_id` — API public không đổi.

## Thứ tự implement

Làm xong bước trước mới mở bước sau:

1. Project + plan + module flag
2. Field registry + trần plan
3. Auth password theo schema
4. Key + origin + resolve project
5. `/v1/client/config` + playground API
6. SDK JS tối thiểu
7. Collection CRUD + rule
8. File
9. Realtime theo collection

Không bắt đầu từ gateway mesh, OAuth, hay stream chat.

## Câu hỏi khi thiếu spec

Hỏi lại trước khi đoán:

- Đây là control hay runtime?
- Field này là identifier, profile, hay server state?
- Gọi bằng `pk_` hay `sk_`?
- Test hay live?

Không tự invent payment, org/SAML, hay microservice mới.
