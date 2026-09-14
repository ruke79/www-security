-- Training lab schema - H2 (in-memory). Tables prefixed lab_ to stay isolated
-- from the rest of the app (which is fully in-memory).
DROP TABLE IF EXISTS lab_products;
DROP TABLE IF EXISTS lab_users;
DROP TABLE IF EXISTS lab_comments;

CREATE TABLE lab_products (
    id    INT PRIMARY KEY,
    name  VARCHAR(100),
    price INT
);

-- A "sensitive" table the SQL-injection UNION attack can exfiltrate.
CREATE TABLE lab_users (
    id       INT PRIMARY KEY,
    username VARCHAR(100),
    password VARCHAR(100)
);

-- Backing store for the stored-XSS lab.
CREATE TABLE lab_comments (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    author  VARCHAR(100),
    comment VARCHAR(1000)
);
