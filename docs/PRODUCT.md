# BeeBox — flow người dùng

Tài liệu này mô tả sản phẩm theo đường đi của người dùng, không theo service.

Có hai người:

1. **Chủ project** — lập trình viên / agency, vào BeeBox để lấy backend.
2. **User cuối** — khách của chủ project, chỉ thấy frontend.

---

## 1. Chủ project tạo tài khoản BeeBox

Đăng ký trên dashboard BeeBox.

Đây là tài khoản **điều khiển**, không phải user của app họ đang xây.

Họ thấy danh sách project và gói đang dùng.

---

## 2. Tạo project

- Tên: `Quan Tra Dao`
- Slug: `quan-tra-dao` → URL `https://quan-tra-dao.api.beebox.dev`
- Môi trường mặc định: **Test**

Project lúc này chưa public API cho đến khi bật ít nhất một module.

---

## 3. Chọn gói

Free hoặc Pro.

Gói quyết định trần module, số field, số collection, file, realtime, domain.

Gói **không** quyết định field tên gì được phép. `fullName` hay `firstName` đều được nếu còn slot.

Có thể bắt đầu Free, nâng Pro sau, không tạo lại project.

---

## 4. Chọn module

Tick chức năng cần dùng.

Ví dụ Free:

- `auth.password` (sign-up, sign-in, reset)
- `users.profile`

Ví dụ Pro:

- `auth.password`
- `auth.otp`
- `auth.oauth.google`
- `users.profile`
- `data.collections`
- `file.storage`
- `realtime.collection`

Module tắt thì route không tồn tại (hoặc 403 + bảo nâng gói).

Sign-up và sign-in **không** phải hai module. Chúng là route của `auth.password`.

---

## 5. Chọn field

Sau khi bật auth, cấu hình user của **project này**.

### Identifier

- Email và/hoặc phone
- Bắt buộc ít nhất một
- Unique theo project, không unique toàn hệ thống

### Field tùy chọn

Trong trần gói. Type: string, number, bool, enum, date, file (tùy gói).

Ví dụ User A (Free): `fullName`, `email`, `phone`  
Ví dụ User B (Pro): `firstName`, `lastName`, `email`, `phone`, `gender`

Không cho chủ project tạo field `isVerified` / `isAdmin` như input client. Đó là state server.

OAuth không nằm list field. OAuth là module bước 4.

---

## 6. Nhận backend

Dashboard hiện:

```text
Backend URL     https://quan-tra-dao.api.beebox.dev
Publishable key pk_test_...
Secret key      sk_test_...     (show một lần)
```

Snippet:

```js
const client = createBeeBox({
  url: "https://quan-tra-dao.api.beebox.dev",
  publishableKey: "pk_test_xxx",
})
```

`pk_` được đưa vào frontend.  
`sk_` chỉ server / script admin của chủ project.

---

## 7. Playground

Trong dashboard, chưa cần repo frontend.

- Form đăng ký render đúng field project
- Đăng ký / đăng nhập thử
- Xem JSON `/v1/auth/me`
- Tab Users thấy user test

Playground dùng instance Test.

---

## 8. Frontend

Chủ project tự làm UI.

Gắn URL + publishable key. Lấy schema form từ:

```http
GET /v1/client/config
```

Trả về module đang bật + field signup + identifier. Frontend có thể tự vẽ form, không hardcode tên cột.

Auth runtime:

```http
POST /v1/auth/sign-up
POST /v1/auth/sign-in
GET  /v1/auth/me
POST /v1/auth/sign-out
```

Body phụ thuộc schema project, không phụ thuộc một struct `FullName` cứng trong code BeeBox.

---

## 9. Allow origin

Dashboard thêm origin được phép dùng `pk_` trên browser:

- `http://localhost:3000`
- `https://tradao.vn`

Thiếu bước này thì “chỉ dán URL” không an toàn.

---

## 10. User cuối

Vào frontend của chủ project, không thấy BeeBox.

Đăng ký → request vào `{slug}.api.beebox.dev` → user được tạo **trong project đó**.

Cùng email có thể tồn tại ở project khác.

Chủ project quản lý user trong dashboard (khóa, xem session). Không impersonate ở bản đầu nếu chưa cần.

---

## 11. Thêm chức năng sau

URL backend không đổi.

Nâng Pro → bật OAuth → dán Google client id → frontend thêm nút.

Bật collection `products` (`name`, `price`, `image`) →

```http
GET  /v1/data/products
POST /v1/data/products
```

Rule mặc định: đọc public hoặc theo cấu hình; ghi cần session.

Realtime: subscribe theo collection khi record đổi. Không phải chat server riêng.

---

## 12. Production

- Tạo instance Live, data không trộn Test
- `pk_live_` / `sk_live_`
- Frontend đổi key + URL live
- Pro: custom domain `api.tradao.vn`

---

## Việc chủ project không làm

- Không viết API login
- Không migrate Postgres
- Không hash password, xoay session, gửi OTP
- Không tách microservice

Họ chọn module, chọn field đúng gói, gắn URL + `pk_`, allow origin, làm UI.
