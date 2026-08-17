require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuração do PostgreSQL utilizando a DATABASE_URL da nuvem (Neon/Render)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necessário para conexões seguras externas no Neon
    }
});

// Criar tabela de usuários automaticamente se não existir (incluindo a coluna is_approved)
pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_approved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`, (err) => {
    if (err) console.error('Erro ao criar tabela:', err);
    else console.log('Banco PostgreSQL conectado e tabela pronta.');
});

// Rota de Cadastro
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hashedPassword]);
        res.json({ success: true, message: 'Usuário cadastrado com sucesso!' });
    } catch (err) {
        console.error('Erro no cadastro:', err);
        res.status(400).json({ success: false, message: 'Erro: E-mail já cadastrado.' });
    }
});

// Rota de Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        // 1. Verifica se o usuário existe e se a senha bate
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
        }

        // 2. Verifica se a conta foi aprovada pelo administrador
        if (!user.is_approved) {
            return res.status(403).json({ success: false, message: 'Sua conta aguarda liberação do administrador.' });
        }

        // 3. Se passou por tudo, login autorizado!
        res.json({ success: true, message: 'Login autorizado!' });

    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).json({ success: false, message: 'Erro interno no servidor.' });
    }
});

// Rota para listar usuários pendentes
app.get('/api/admin/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, email, is_approved, created_at FROM users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao buscar usuários:', err);
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

// Rota para aprovar o usuário
app.post('/api/admin/approve', async (req, res) => {
    const { userId } = req.body;
    try {
        await pool.query('UPDATE users SET is_approved = TRUE WHERE id = $1', [userId]);
        res.json({ success: true, message: 'Usuário aprovado com sucesso!' });
    } catch (err) {
        console.error('Erro ao aprovar usuário:', err);
        res.status(500).json({ error: 'Erro ao aprovar usuário' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));