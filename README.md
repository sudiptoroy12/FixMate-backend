# 🔧 FixMate Backend

<p align="center">
  <strong>A RESTful API for an On-Demand Device & Home Appliance Repair Platform</strong>
</p>

<p align="center">
  Built with Node.js, Express.js, MongoDB, Better Auth JWT Verification, and Stripe.
</p>

---

## 📌 About the Project

FixMate is an on-demand repair service platform that connects customers with professional technicians for device and home appliance repairs.

This repository contains the backend REST API responsible for authentication verification, user authorization, service management, booking operations, technician workflows, administrative management, and secure online payments.

The backend provides separate permissions for three types of users: Customers, Technicians, and Admins.

## ✨ Key Features

- **Authentication & Authorization**
  - Better Auth JWT verification using `jose`.
  - Remote JWKS-based token verification.
  - Role-based access control.
  - Protected API endpoints.

- **Service Management**
  - Create, update, and delete repair services.
  - Service approval and rejection by administrators.
  - Search and filter available services.
  - Featured services listing.
  - Technician-specific service management.
  - Service availability management.

- **Booking Management**
  - Customers can request repair services.
  - Technicians can accept or reject requests.
  - Update repair progress and completion status.
  - Customers can view and cancel eligible bookings.
  - Administrators can manage booking statuses.

- **Payment Management**
  - Stripe Checkout integration.
  - Secure payment session creation.
  - Stripe webhook signature verification.
  - Payment verification.
  - Duplicate payment prevention.
  - Customer payment history.
  - Technician earnings calculation.
  - Admin transaction management.

- **Admin Dashboard**
  - Dashboard statistics.
  - User management and role updates.
  - Service approval management.
  - Booking management.
  - Transaction monitoring.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Node.js | JavaScript runtime |
| Express.js | Backend REST API |
| MongoDB Atlas | NoSQL database |
| MongoDB Driver | Database operations |
| Better Auth | Authentication provider |
| jose | JWT verification |
| Stripe | Payment processing |
| dotenv | Environment configuration |
| CORS | Cross-origin resource sharing |

## 🗄️ Database Structure

Database name: `fixmate`

| Collection | Description |
|---|---|
| `user` | Stores user and role information |
| `services` | Stores technician repair services |
| `serviceRequests` | Stores customer bookings and repair requests |
| `payments` | Stores payment and transaction records |

A unique MongoDB index on `stripeSessionId` helps prevent duplicate payment records.

## 🔐 Authentication & Authorization

FixMate uses Better Auth for authentication and verifies access tokens on the backend.

JWT verification is implemented using:

- `jose`
- `createRemoteJWKSet()`
- `jwtVerify()`

The backend retrieves public signing keys from the frontend authentication JWKS endpoint:

```text
${CLIENT_URL}/api/auth/jwks
```

### User Roles

| Role | Permissions |
|---|---|
| Customer | Browse services, create bookings, manage eligible bookings, and make payments |
| Technician | Manage services, handle repair requests, update job statuses, and view earnings |
| Admin | Manage users, services, bookings, and transactions |

### Protected API Requests

Include a valid access token in the Authorization header:

```http
Authorization: Bearer YOUR_ACCESS_TOKEN
```

Unauthorized requests return HTTP `401`, while requests without the required role return HTTP `403`.

## 🔗 API Documentation

Base URL:

```text
YOUR_BACKEND_DEPLOYED_URL
```

### 1. General APIs

| Method | Endpoint | Access |
|---|---|---|
| GET | `/` | Public |

### 2. Public Service APIs

| Method | Endpoint | Description | Access |
|---|---|---|---|
| GET | `/api/services` | Get approved services | Public |
| GET | `/api/featured-services` | Get latest 6 featured services | Public |
| GET | `/api/services/:id` | Get individual service details | Public |

**Service filtering and sorting:**

The `/api/services` endpoint supports:

- `search` – Search by service title or category.
- `category` – Filter by service category.
- `serviceMode` – Filter by service mode.
- `sort` – Sort by price or newest.

Available sorting values:

```text
newest
price-asc
price-desc
```

### 3. Technician Service APIs

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/services/my-services` | Get technician's services |
| POST | `/api/services` | Create a new service |
| PATCH | `/api/services/:id` | Update own service |
| DELETE | `/api/services/:id` | Delete own service |
| PATCH | `/api/services/:id/availability` | Update service availability |

All endpoints require Technician authorization.

### 4. Customer Booking APIs

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/service-requests` | Create a repair request |
| GET | `/api/service-requests/customer` | Get customer's bookings |
| PATCH | `/api/service-requests/:id/cancel` | Cancel an eligible booking |

All endpoints require Customer authorization.

### 5. Technician Booking APIs

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/service-requests/technician` | Get assigned repair requests |
| PATCH | `/api/service-requests/:id/status` | Update repair request status |

Technicians can update requests through these statuses:

```text
requested → accepted → in-progress → completed
                  ↘ rejected
```

A technician must be assigned to the request to update its status.

The final repair amount is provided when completing a job