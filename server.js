require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Sessão (cookie HttpOnly)
app.use(session({
    secret: process.env.SESSION_SECRET || 'troque-esta-chave-secreta-lcdpr-pro',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // true no Render (HTTPS)
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 horas
    }
}));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_approved BOOLEAN DEFAULT FALSE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)`, (err) => {
    if (err) console.error('Erro ao criar tabela:', err);
    else console.log('Banco PostgreSQL conectado e tabela pronta.');
});

// ---------- Middlewares de proteção ----------
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) return next();
    // Se for página HTML, redireciona; se for API, 401
    if (req.accepts('html')) return res.redirect('/?login=required');
    return res.status(401).json({ success: false, message: 'Não autenticado.' });
}

function requireAdmin(req, res, next) {
    if (req.session && req.session.userId && req.session.isAdmin) return next();
    if (req.accepts('html')) return res.redirect('/?login=required');
    return res.status(403).json({ success: false, message: 'Acesso restrito a administradores.' });
}

// ---------- APIs públicas ----------
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'E-mail e senha são obrigatórios.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
            [email, hashedPassword]
        );
        res.json({ success: true, message: 'Cadastro realizado! Aguarde aprovação do administrador.' });
    } catch (err) {
        console.error('Erro no cadastro:', err);
        res.status(400).json({ success: false, message: 'Erro: E-mail já cadastrado.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ success: false, message: 'E-mail ou senha incorretos.' });
        }
        if (!user.is_approved) {
            return res.status(403).json({
                success: false,
                message: 'Sua conta aguarda liberação do administrador.'
            });
        }

        // Grava sessão
        req.session.userId = user.id;
req.session.email = user.email;
req.session.isAdmin = !!user.is_admin;

req.session.save((sessionErr) => {
    if (sessionErr) {
        console.error('Erro ao salvar sessão:', sessionErr);

        return res.status(500).json({
            success: false,
            message: 'Não foi possível criar a sessão de login.'
        });
    }

    console.log('Sessão criada com sucesso:', {
        userId: req.session.userId,
        email: req.session.email,
        isAdmin: req.session.isAdmin,
        sessionID: req.sessionID
    });

    res.json({
        success: true,
        message: 'Login autorizado!',
        isAdmin: !!user.is_admin
    });
});
    } catch (err) {
        console.error('Erro no login:', err);
        res.status(500).json({ success: false, message: 'Erro interno no servidor.' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

app.get('/api/me', (req, res) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ success: false, authenticated: false });
    }
    res.json({
        success: true,
        authenticated: true,
        email: req.session.email,
        isAdmin: !!req.session.isAdmin
    });
});

// ---------- APIs admin (protegidas) ----------
app.get('/api/admin/users', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, email, is_approved, is_admin, created_at FROM users ORDER BY created_at DESC'
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Erro ao buscar usuários:', err);
        res.status(500).json({ error: 'Erro ao buscar usuários' });
    }
});

app.post('/api/admin/approve', requireAdmin, async (req, res) => {
    const { userId } = req.body;
    try {
        await pool.query('UPDATE users SET is_approved = TRUE WHERE id = $1', [userId]);
        res.json({ success: true, message: 'Usuário aprovado com sucesso!' });
    } catch (err) {
        console.error('Erro ao aprovar usuário:', err);
        res.status(500).json({ error: 'Erro ao aprovar usuário' });
    }
});

// ---------- Páginas protegidas (ANTES do static) ----------
app.get('/dashboard.html', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin.html', requireAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Arquivos estáticos públicos (index, CSS, JS, imagens...)
// NÃO coloque dashboard.html / admin.html acessíveis só por static sem proteção
app.use(express.static(path.join(__dirname, 'public'), {
    // opcional: index
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));