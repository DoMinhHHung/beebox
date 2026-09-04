# BeeBox

Backend sẵn cho người chỉ muốn viết frontend.

Tạo project → chọn chức năng theo gói → chọn field → nhận URL + key → gắn vào app. Không viết server, không tạo bảng Postgres, không canh session.

## Ý tưởng

BeeBox là BaaS đóng gói theo plan. Mỗi project là một backend instance (một URL), chạy trên hạ tầng chung.

Hai loại người dùng:

- **Chủ project** — vào `beebox.dev`, cấu hình backend, làm frontend.
- **User cuối** — dùng app của chủ project, không biết BeeBox.

Không phải clone Clerk. Auth chỉ là cửa. Sản phẩm là: schema project quyết định API, frontend chỉ gắn URL + public key.

## Flow ngắn

1. Chủ project tạo project, chọn Test hoặc Live.
2. Chọn gói Free / Pro. Gói chặn **số lượng và sức mạnh**, không chặn tên field.
3. Bật module: `auth.password`, `auth.otp`, `auth.oauth.*`, `users.profile`, `data.collections`, `file.storage`, `realtime.collection`.
4. Chọn identifier (email và/hoặc phone) + field user trong trần gói.
5. Nhận:

   ```text
   https://{slug}.api.beebox.dev
   pk_test_... / pk_live_...
   sk_test_... / sk_live_...   (chỉ hiện một lần)
   ```

6. Thử trên Playground trong dashboard.
7. Frontend:

   ```js
   createBeeBox({
     url: "https://quan-tra-dao.api.beebox.dev",
     publishableKey: "pk_test_xxx",
   })
   ```

8. Allow origin (`localhost`, domain production). Không chỉ dán URL.
9. User cuối đăng ký / đăng nhập / gọi data trên đúng project đó.

Chi tiết từng bước: [docs/PRODUCT.md](docs/PRODUCT.md).

## Quyết định đã chốt

| Có | Không |
|---|---|
| 1 Postgres, shared schema, `project_id` + JSONB + RLS | Schema / database Postgres per project |
| Public key + secret key + allow origin | Chỉ phát URL, không key |
| Module = plugin trong process | `beebox-module-signin` / `signup` là microservice |
| Sign-up, sign-in, reset cùng module `auth` | Tách service theo từng màn hình |
| Identifier ≠ field tùy chọn ≠ OAuth | Nhét `gender` và OAuth cùng một list field |
| `isVerified` do server | Cho client gửi `isVerified` |
| Control plane + runtime (có thể 1 binary) | Gateway + plans + projects + từng module = service riêng ngày 1 |
| Playground trước khi viết frontend | Bắt họ đoán API |

## Hai mặt API

- **Control** — dashboard BeeBox: project, plan, module, field, key, origin, users.
- **Runtime** — URL khách gắn vào frontend: auth, me, data, file, realtime.

Khách chỉ đụng runtime. Control không public cho user cuối.

## Plan (hướng)

Hạn mức, không phải tên cột (`fullName` Free / `firstName` Pro).

| | Free | Pro |
|---|---|---|
| Auth | email + password | + OTP, OAuth |
| Custom user fields | 3 | 20 |
| Collection | 1 | 20 |
| Realtime / file | hạn chế | có |
| Custom domain | không | có |

## Stack

- Go
- Postgres
- Redis
- Modular monolith, Clean Architecture **trong module**
- Worker riêng khi có mail / SMS / webhook

Cắt service sau, khi có lý do: `control` / `runtime` / `worker` / `realtime`. Không cắt `plans` hay `signin`.

## Repo

```text
beebox/
  cmd/                 control, runtime, worker
  internal/
    project/
    billing/           plans, quota
    iam/               keys, origin
    schema/            field registry
    module/            auth, data, file, realtime
    gateway/           resolve project, rate limit
  docs/
  AGENTS.md
  README.md
```

Lúc mới: một Go module, một hoặc hai process. Chưa cần nhiều repo.

## Trạng thái

Đang ở bước định hướng sản phẩm. Chưa có runtime production.

Thứ tự implement:

1. Project + plan + module flag
2. User field registry theo trần plan
3. Auth theo field đã chọn
4. URL + `pk_` / `sk_`
5. `/v1/client/config` + playground
6. SDK JS mỏng
7. Collection CRUD
8. File / realtime

## Gateway

HTTP edge tối thiểu. Chưa auth, chưa resolve project.

```bash
cd beebox-gateway && go test -race ./...
cd beebox-gateway && go run ./cmd/gateway
```

Listen `:8080`. Env: `BEEBOX_HTTP_ADDR`, `BEEBOX_SHUTDOWN_TIMEOUT`, `BEEBOX_REQUEST_TIMEOUT` (timeout mặc định `10s`). `GET /health/live` và `GET /health/ready` trả `{"status":"ok"}`.

```bash
cd beebox-apperror && go test ./...
```

## Tài liệu

- [docs/PRODUCT.md](docs/PRODUCT.md) — flow người dùng
- [AGENTS.md](AGENTS.md) — luật cho AI khi đọc và sửa code
