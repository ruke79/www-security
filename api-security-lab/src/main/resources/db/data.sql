-- Training lab seed data (shared by H2 / PostgreSQL / MySQL).
INSERT INTO lab_products (id, name, price) VALUES (1, 'Lemon Cupcake', 3);
INSERT INTO lab_products (id, name, price) VALUES (2, 'Red Velvet Cupcake', 4);
INSERT INTO lab_products (id, name, price) VALUES (3, 'Peanut Butter Cupcake', 4);

-- Demo-only fake credentials, present so a UNION-based SQL injection has
-- something "sensitive" to leak. NOT real accounts.
INSERT INTO lab_users (id, username, password) VALUES (1, 'admin', 'S3cr3t-demo-pw!');
INSERT INTO lab_users (id, username, password) VALUES (2, 'alice', 'alice-demo-pw');
