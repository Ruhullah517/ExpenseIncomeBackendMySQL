const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(bodyParser.json());
app.use(cors({
    origin: '*',
    methods: 'GET,POST,PUT,DELETE',
    credentials: true,
    optionsSuccessStatus: 200
}));

// Initialize MySQL database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err.message);
    } else {
        console.log('Connected to MySQL database');

        db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL
            ) ENGINE=InnoDB;
        `, (err) => {
            if (err) {
                console.error('Error creating users table:', err);
            } else {
                console.log('Users table created or already exists.');
            }
        });

        // Create 'accounts' table
        db.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                admin_id INT NOT NULL,
                FOREIGN KEY (admin_id) REFERENCES users(id)
            ) ENGINE=InnoDB;
        `, (err) => {
            if (err) {
                console.error('Error creating accounts table:', err);
            } else {
                console.log('Accounts table created or already exists.');
            }
        });

        // Create 'user_account' table
        db.query(`
            CREATE TABLE IF NOT EXISTS user_account (
                user_id INT NOT NULL,
                account_id INT NOT NULL,
                role VARCHAR(50) NOT NULL,
                PRIMARY KEY (user_id, account_id),
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            ) ENGINE=InnoDB;
        `, (err) => {
            if (err) {
                console.error('Error creating user_account table:', err);
            } else {
                console.log('User_Account table created or already exists.');
            }
        });

        // Create 'expenses' table
        db.query(`
            CREATE TABLE IF NOT EXISTS expenses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                amount DECIMAL(10, 2) NOT NULL,
                date DATE NOT NULL,
                created_by INT NOT NULL,
                type VARCHAR(50) NOT NULL,
                image_path TEXT,
                account_id INT NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users(id),
                FOREIGN KEY (account_id) REFERENCES accounts(id)
            ) ENGINE=InnoDB;
        `, (err) => {
            if (err) {
                console.error('Error creating expenses table:', err);
            } else {
                console.log('Expenses table created or already exists.');
            }
        });

        console.log('Tables created or already exist');
    }
});

// Routes will go here...
app.post('/signup', (req, res) => {
    const { email, password, name } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    // Check if user with the provided email already exists
    const checkUserSql = 'SELECT * FROM users WHERE email = ?';
    db.query(checkUserSql, [email], (err, results) => {
        if (err) return res.status(500).send('Server error');

        if (results.length > 0) return res.status(400).send('User already exists');

        // Insert new user into the 'users' table
        const insertUserSql = 'INSERT INTO users (email, password, name) VALUES (?, ?, ?)';
        db.query(insertUserSql, [email, hashedPassword, name], (err, result) => {
            if (err) return res.status(500).send('Server error');

            const userId = result.insertId;

            // Create personal account for the user
            const createAccountSql = 'INSERT INTO accounts (admin_id) VALUES (?)';
            db.query(createAccountSql, [userId], (err, result) => {
                if (err) return res.status(500).send('Error creating personal account');

                const accountId = result.insertId;

                // Associate the user with the personal account in 'user_account' table
                const associateUserSql = 'INSERT INTO user_account (user_id, account_id, role) VALUES (?, ?, ?)';
                db.query(associateUserSql, [userId, accountId, 'admin'], (err) => {
                    if (err) return res.status(500).send('Error associating user with personal account');

                    res.status(200).send('User and personal account created successfully');
                });
            });
        });
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
        if (err || results.length === 0) return res.status(404).send('User not found');

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) return res.status(401).send('Invalid password');

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: 86400 });
        res.status(200).send({ auth: true, token: token });
    });
});

app.get('/users/:id', (req, res) => {
    const userId = req.params.id;
    db.query('SELECT name FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) return res.status(500).send('Server error');
        if (results.length === 0) return res.status(404).send('User not found');
        res.send(results[0]);
    });
});

app.post('/add-expense', (req, res) => {
    const { name, amount, date, created_by, type, image_path, account_id } = req.body;

    const sql = `
        INSERT INTO expenses (name, amount, date, created_by, type, image_path, account_id) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(sql, [name, amount, date, created_by, type, image_path, account_id], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error inserting expense into database');
        }
        res.status(200).send('Expense added successfully');
    });
});

app.get('/accounts/current/:userId', (req, res) => {
    const userId = req.params.userId;
    const sql = `
        SELECT a.id, a.admin_id 
        FROM accounts a
        JOIN user_account ua ON ua.account_id = a.id
        WHERE ua.user_id = ? AND ua.role = 'admin'
    `;
    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching account details');
        res.status(200).json(results);
    });
});

app.get('/accounts/:accountId/expenses', (req, res) => {
    const { accountId } = req.params;
    const sql = 'SELECT * FROM expenses WHERE account_id = ?';
    db.query(sql, [accountId], (err, results) => {
        if (err) return res.status(500).send('Error fetching expenses');
        res.status(200).send(results);
    });
});

app.get('/', (req, res) => {
    res.status(200).send("backend is running")
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));
