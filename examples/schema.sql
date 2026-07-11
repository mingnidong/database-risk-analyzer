-- Example schema for migrate-risk demos

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_users_email ON users(email);

CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_events_user_id ON events(user_id);
CREATE INDEX idx_events_created_at ON events(created_at);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    total_cents INTEGER NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE orders
    ADD CONSTRAINT fk_orders_user
    FOREIGN KEY (user_id) REFERENCES users(id);

CREATE TABLE invoices (
    id SERIAL PRIMARY KEY,
    order_id INTEGER NOT NULL,
    amount_cents INTEGER NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE invoices
    ADD CONSTRAINT fk_invoices_order
    FOREIGN KEY (order_id) REFERENCES orders(id);

CREATE INDEX idx_invoices_order_id ON invoices(order_id);
