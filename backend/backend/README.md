# Jay Bhutnath Agri Supplier — Backend

## Run
    npm install
    cp .env.example .env     # set JWT_SECRET and ADMIN_PASS
    npm start                # http://localhost:3000

Put the website's HTML in `./public/index.html` and it is served from the same server.

## API (JSON, send `Authorization: Bearer <token>`)
| Who | Method & path | Purpose |
|---|---|---|
| all | POST /api/auth/register `{role,name,phone,password}` | Sign up (status = pending) |
| all | POST /api/auth/login `{role,username,password}` | Log in (admin uses username; others use mobile number) |
| all | GET /api/me | Current user and approval status |
| approved | GET /api/products | Product list |
| farmer, trader | POST /api/orders `{items:[{productId,qty}],address}` | Place order; response includes the OTP |
| farmer, trader | GET /api/orders | Own orders with OTP |
| partner | GET /api/partner/orders | Assigned orders |
| partner | POST /api/partner/orders/:id/start | Packed → Out for delivery |
| partner | POST /api/partner/orders/:id/deliver `{otp}` | Verify OTP → Delivered (5 tries) |
| admin | GET /api/admin/users, PATCH /api/admin/users/:id/status `{status}` | Approve / reject |
| admin | POST/PATCH/DELETE /api/admin/products[/:id] | Add products, change prices and stock |
| admin | GET /api/admin/orders, PATCH /api/admin/orders/:id `{status,partnerId}` | Track, assign partner, cancel |
| admin | POST /api/admin/orders/:id/reset-otp | New OTP after lockout |
| admin | GET /api/admin/stats | Dashboard numbers |

## Going live checklist
- Use HTTPS (e.g. nginx or Caddy in front, or a host such as Render/Railway).
- Wire `sendSms()` in server.js to an SMS provider (Twilio, MSG91, Fast2SMS) so OTPs reach customers by SMS.
- Data is stored in `data.json`. Move to PostgreSQL or MongoDB before heavy traffic or multiple servers.

## Live location endpoints
| Who | Method & path | Purpose |
|---|---|---|
| partner | POST /api/partner/location `{lat,lng,accuracy}` | Send position every 5–10 s while sharing |
| partner | PATCH /api/partner/duty `{duty}` | Go on/off duty (off duty clears location) |
| admin | GET /api/admin/partners | All partners with last location and active orders (poll every 5 s) |
| farmer, trader | GET /api/orders/:id/track | Partner name, phone and location while the order is out for delivery |

## Website (connected to this API)
`public/index.html` is the full website wired to the API. Start the server and open http://localhost:3000.
Partners tap "Go on duty and share location"; the admin's Delivery tracking tab and the customer's order card show a live OpenStreetMap pin that refreshes every 5 seconds.
Browsers only share location on HTTPS or localhost, so use HTTPS when you deploy.
