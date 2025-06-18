import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import PDFDocument from 'pdfkit';

const app = express();
const port = process.env.PORT || 5000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(cookieParser());

// Database Connection - PostgreSQL
const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    rejectUnauthorized: false
  }
});

// Test database connection
async function testConnection() {
  let client;
  try {
    client = await pool.connect();
    console.log('🟢 PostgreSQL conectado com sucesso!');
  } catch (error) {
    console.error('🔴 Erro ao conectar no PostgreSQL:', error);
    process.exit(1);
  } finally {
    if (client) client.release();
  }
}

// Rota de teste
app.get('/', (req, res) => {
  res.send('Servidor com PostgreSQL ativo 🚀');
});

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ message: 'Acesso não autorizado' });
  
  jwt.verify(token, process.env.JWT_SECRET || 'secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
};

// Admin role middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Acesso negado. Requer privilégios de administrador.' });
  }
  next();
};

// Authentication routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    const user = result.rows[0];
    
    // Since we're storing passwords as plain text as requested
    if (password !== user.password) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'secret_key',
      { expiresIn: '24h' }
    );
    
    // Remove password from user object
    delete user.password;
    
    res.json({ token, user });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Erro no servidor' });
  }
});

// Products routes
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ message: 'Erro ao buscar produtos' });
  }
});

app.get('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM products WHERE id = $1',
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching product:', error);
    res.status(500).json({ message: 'Erro ao buscar produto' });
  }
});

// Create product with serial_code duplicate check
app.post('/api/products', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, category, price, stock, serial_code } = req.body;

    // Check for duplicate serial_code
    const existingResult = await pool.query(
      'SELECT * FROM products WHERE serial_code = $1',
      [serial_code]
    );

    if (existingResult.rows.length > 0) {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }

    const result = await pool.query(
      'INSERT INTO products (name, category, price, stock, serial_code) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, category, price, stock, serial_code]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating product:', error);
    if (error.code === '42703') {
      return res.status(500).json({ message: 'Erro: Coluna serial_code não encontrada na tabela de produtos. Contate o administrador.' });
    }
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }
    res.status(500).json({ message: 'Erro ao criar produto' });
  }
});

// Update product with serial_code duplicate check
app.put('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, category, price, stock, serial_code } = req.body;

    // Check for duplicate serial_code, excluding the current product
    const existingResult = await pool.query(
      'SELECT * FROM products WHERE serial_code = $1 AND id != $2',
      [serial_code, req.params.id]
    );

    if (existingResult.rows.length > 0) {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }

    const result = await pool.query(
      'UPDATE products SET name = $1, category = $2, price = $3, stock = $4, serial_code = $5 WHERE id = $6 RETURNING *',
      [name, category, price, stock, serial_code, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating product:', error);
    if (error.code === '42703') {
      return res.status(500).json({ message: 'Erro: Coluna serial_code não encontrada na tabela de produtos. Contate o administrador.' });
    }
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Código serial já está em uso' });
    }
    res.status(500).json({ message: 'Erro ao atualizar produto' });
  }
});

// Delete product
app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM products WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Produto não encontrado' });
    }
    
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({ message: 'Erro ao excluir produto' });
  }
});

// Users routes
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, username, name, role FROM users');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Erro ao buscar usuários' });
  }
});

app.get('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, name, role FROM users WHERE id = $1',
      [req.params.id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Erro ao buscar usuário' });
  }
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    
    // Check if username already exists
    const existingResult = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    
    if (existingResult.rows.length > 0) {
      return res.status(400).json({ message: 'Nome de usuário já existe' });
    }
    
    const result = await pool.query(
      'INSERT INTO users (username, password, name, role) VALUES ($1, $2, $3, $4) RETURNING id, username, name, role',
      [username, password, name, role]
    );
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error('Error creating user:', error);
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Nome de usuário já existe' });
    }
    res.status(500).json({ message: 'Erro ao criar usuário' });
  }
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { username, password, name, role } = req.body;
    
    let result;
    if (password) {
      result = await pool.query(
        'UPDATE users SET username = $1, password = $2, name = $3, role = $4 WHERE id = $5 RETURNING id, username, name, role',
        [username, password, name, role, req.params.id]
      );
    } else {
      result = await pool.query(
        'UPDATE users SET username = $1, name = $2, role = $3 WHERE id = $4 RETURNING id, username, name, role',
        [username, name, role, req.params.id]
      );
    }
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating user:', error);
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Nome de usuário já existe' });
    }
    res.status(500).json({ message: 'Erro ao atualizar usuário' });
  }
});

app.delete('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM users WHERE id = $1 RETURNING *',
      [req.params.id]
    );
    
    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Usuário não encontrado' });
    }
    
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ message: 'Erro ao excluir usuário' });
  }
});

// Sales routes
app.get('/api/sales', authenticateToken, async (req, res) => {
  try {
    let query = `
      SELECT s.*, u.name as vendor_name 
      FROM sales s
      JOIN users u ON s.vendor_id = u.id
    `;
    
    const params = [];
    
    // If not admin, only show own sales
    if (req.user.role !== 'admin') {
      query += ' WHERE s.vendor_id = $1';
      params.push(req.user.id);
    }
    
    query += ' ORDER BY s.date DESC';
    
    const salesResult = await pool.query(query, params);
    
    // Get items for each sale
    const sales = salesResult.rows;
    for (const sale of sales) {
      const itemsResult = await pool.query(
        'SELECT * FROM sale_items WHERE sale_id = $1',
        [sale.id]
      );
      sale.items = itemsResult.rows;
    }
    
    res.json(sales);
  } catch (error) {
    console.error('Error fetching sales:', error);
    res.status(500).json({ message: 'Erro ao buscar vendas' });
  }
});

app.get('/api/sales/:id', authenticateToken, async (req, res) => {
  try {
    const salesResult = await pool.query(
      `SELECT s.*, u.name as vendor_name 
       FROM sales s
       JOIN users u ON s.vendor_id = u.id
       WHERE s.id = $1`,
      [req.params.id]
    );
    
    if (salesResult.rows.length === 0) {
      return res.status(404).json({ message: 'Venda não encontrada' });
    }
    
    const sale = salesResult.rows[0];
    
    // Check if user has access to this sale
    if (req.user.role !== 'admin' && sale.vendor_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }
    
    // Get items for this sale
    const itemsResult = await pool.query(
      'SELECT * FROM sale_items WHERE sale_id = $1',
      [sale.id]
    );
    
    sale.items = itemsResult.rows;
    
    res.json(sale);
  } catch (error) {
    console.error('Error fetching sale:', error);
    res.status(500).json({ message: 'Erro ao buscar venda' });
  }
});

app.post('/api/sales', authenticateToken, async (req, res) => {
  let client;
  try {
    client = await pool.connect();
    await client.query('BEGIN');
    
    const { vendor_id, vendor_name, total, payment, change, items } = req.body;
    
    // Input validation
    if (!items || !Array.isArray(items) || items.length === 0) {
      throw new Error('A venda deve conter pelo menos um item');
    }
    
    // Validate stock for all items
    for (const item of items) {
      if (!item.product_id || !item.quantity || item.quantity <= 0) {
        throw new Error(`Dados inválidos para o item: ${item.product_name || 'Desconhecido'}`);
      }
      
      const productResult = await client.query(
        'SELECT stock, name FROM products WHERE id = $1',
        [item.product_id]
      );
      
      if (productResult.rows.length === 0) {
        throw new Error(`Produto com ID ${item.product_id} não encontrado`);
      }
      
      const product = productResult.rows[0];
      if (product.stock < item.quantity) {
        throw new Error(
          `Estoque insuficiente para ${product.name}. Disponível: ${product.stock}, Solicitado: ${item.quantity}`
        );
      }
    }
    
    // Insert sale
    const saleResult = await client.query(
      'INSERT INTO sales (vendor_id, date, total, payment, change_amount) VALUES ($1, NOW(), $2, $3, $4) RETURNING id',
      [vendor_id, total, payment, change]
    );
    
    const saleId = saleResult.rows[0].id;
    
    // Insert sale items and update product stock
    for (const item of items) {
      await client.query(
        'INSERT INTO sale_items (sale_id, product_id, product_name, price, quantity, total) VALUES ($1, $2, $3, $4, $5, $6)',
        [saleId, item.product_id, item.product_name, item.price, item.quantity, item.total]
      );
      
      // Update product stock
      await client.query(
        'UPDATE products SET stock = stock - $1 WHERE id = $2',
        [item.quantity, item.product_id]
      );
    }
    
    await client.query('COMMIT');
    
    // Get the created sale with items
    const createdSaleResult = await client.query(
      `SELECT s.*, u.name as vendor_name 
       FROM sales s
       JOIN users u ON s.vendor_id = u.id
       WHERE s.id = $1`,
      [saleId]
    );
    
    const createdSale = createdSaleResult.rows[0];
    
    // Get items for this sale
    const saleItemsResult = await client.query(
      'SELECT * FROM sale_items WHERE sale_id = $1',
      [saleId]
    );
    
    createdSale.items = saleItemsResult.rows;
    
    res.status(201).json(createdSale);
  } catch (error) {
    if (client) await client.query('ROLLBACK');
    console.error('Error creating sale:', error, { saleData: req.body });
    res.status(400).json({ message: error.message || 'Erro ao criar venda' });
  } finally {
    if (client) client.release();
  }
});

// Reports routes
app.get('/api/reports/sales', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    
    let query = `
      SELECT s.*, u.name as vendor_name 
      FROM sales s
      JOIN users u ON s.vendor_id = u.id
    `;
    
    const params = [];
    
    if (startDate && endDate) {
      query += ' WHERE s.date BETWEEN $1 AND $2';
      params.push(startDate, endDate);
    }
    
    query += ' ORDER BY s.date DESC';
    
    const salesResult = await pool.query(query, params);
    
    // Get items for each sale
    const sales = salesResult.rows;
    for (const sale of sales) {
      const itemsResult = await pool.query(
        'SELECT * FROM sale_items WHERE sale_id = $1',
        [sale.id]
      );
      sale.items = itemsResult.rows;
    }
    
    res.json(sales);
  } catch (error) {
    console.error('Error fetching sales report:', error);
    res.status(500).json({ message: 'Erro ao buscar relatório de vendas' });
  }
});

app.get('/api/reports/top-products', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { limit } = req.query;
    const limitValue = limit ? parseInt(limit) : 10;
    
    const result = await pool.query(`
      SELECT 
        si.product_id,
        si.product_name,
        SUM(si.quantity) as total_quantity,
        SUM(si.total) as total_sales
      FROM 
        sale_items si
      GROUP BY 
        si.product_id, si.product_name
      ORDER BY 
        total_quantity DESC
      LIMIT $1
    `, [limitValue]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching top products:', error);
    res.status(500).json({ message: 'Erro ao buscar produtos mais vendidos' });
  }
});

app.get('/api/reports/sales-by-vendor/:vendorId', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { vendorId } = req.params;
    
    const result = await pool.query(`
      SELECT 
        s.*,
        u.name as vendor_name
      FROM 
        sales s
      JOIN 
        users u ON s.vendor_id = u.id
      WHERE 
        s.vendor_id = $1
      ORDER BY 
        s.date DESC
    `, [vendorId]);
    
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching sales by vendor:', error);
    res.status(500).json({ message: 'Erro ao buscar vendas por vendedor' });
  }
});

// New endpoint to fetch unique categories
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != \'\' ORDER BY category');
    const categoryList = result.rows.map(row => row.category);
    res.json(categoryList);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ message: 'Erro ao buscar categorias' });
  }
});

// Generate receipt PDF
app.get('/api/receipts/:id', authenticateToken, async (req, res) => {
  try {
    const salesResult = await pool.query(
      `SELECT s.*, u.name as vendor_name 
       FROM sales s
       JOIN users u ON s.vendor_id = u.id
       WHERE s.id = $1`,
      [req.params.id]
    );

    if (salesResult.rows.length === 0) {
      return res.status(404).json({ message: 'Venda não encontrada' });
    }

    const sale = salesResult.rows[0];

    // Check if user has access to this sale
    if (req.user.role !== 'admin' && sale.vendor_id !== req.user.id) {
      return res.status(403).json({ message: 'Acesso negado' });
    }

    const itemsResult = await pool.query(
      'SELECT * FROM sale_items WHERE sale_id = $1',
      [sale.id]
    );

    // Create PDF
    const doc = new PDFDocument();
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=recibo-venda-${sale.id}.pdf`);
    doc.pipe(res);

    // Header
    doc.fontSize(20).text('RECIBO DE VENDA', { align: 'center' });
    doc.fontSize(12).text('Sistema de Gestão de Loja', { align: 'center' });
    doc.moveDown();

    // Sale details
    doc.fontSize(10);
    doc.text(`Venda #: ${sale.id}`);
    doc.text(`Data: ${new Date(sale.date).toLocaleDateString('pt-BR')} ${new Date(sale.date).toLocaleTimeString('pt-BR')}`);
    doc.text(`Vendedor: ${sale.vendor_name || 'Desconhecido'}`);
    doc.moveDown();

    // Items table
    const tableTop = doc.y;
    const itemWidth = 200;
    const priceWidth = 80;
    const qtyWidth = 50;
    const totalWidth = 80;
    const startX = 50;

    // Headers
    doc.fontSize(10).font('Helvetica-Bold');
    doc.text('Produto', startX, tableTop);
    doc.text('Preço Unit.', startX + itemWidth, tableTop, { width: priceWidth, align: 'right' });
    doc.text('Qtd', startX + itemWidth + priceWidth, tableTop, { width: qtyWidth, align: 'right' });
    doc.text('Total', startX + itemWidth + priceWidth + qtyWidth, tableTop, { width: totalWidth, align: 'right' });

    // Divider
    doc.moveTo(startX, tableTop + 15).lineTo(startX + itemWidth + priceWidth + qtyWidth + totalWidth, tableTop + 15).stroke();

    // Rows
    doc.font('Helvetica');
    let y = tableTop + 20;
    itemsResult.rows.forEach((item) => {
      doc.text(item.product_name || 'N/A', startX, y, { width: itemWidth });
      doc.text(
        `MZN ${Number(item.price).toFixed(2)}`,
        startX + itemWidth,
        y,
        { width: priceWidth, align: 'right' }
      );
      doc.text(item.quantity.toString(), startX + itemWidth + priceWidth, y, { width: qtyWidth, align: 'right' });
      doc.text(
        `MZN ${Number(item.total).toFixed(2)}`,
        startX + itemWidth + priceWidth + qtyWidth,
        y,
        { width: totalWidth, align: 'right' }
      );
      y += 15;
    });

    // Summary
    y += 10;
    doc.font('Helvetica-Bold');
    doc.text(`Total: MZN ${Number(sale.total).toFixed(2)}`, startX + itemWidth + priceWidth + qtyWidth, y, {
      width: totalWidth,
      align: 'right',
    });
    y += 15;
    doc.text(`Pagamento: MZN ${Number(sale.payment).toFixed(2)}`, startX + itemWidth + priceWidth + qtyWidth, y, {
      width: totalWidth,
      align: 'right',
    });
    y += 15;
    doc.text(`Troco: MZN ${Number(sale.change_amount).toFixed(2)}`, startX + itemWidth + priceWidth + qtyWidth, y, {
      width: totalWidth,
      align: 'right',
    });

    // Footer
    doc.font('Helvetica').fontSize(8);
    doc.text('Obrigado pela preferência!', 0, y + 25, { align: 'center', width: 595 });

    doc.end();
  } catch (error) {
    console.error('Error generating receipt:', error);
    res.status(500).json({ message: 'Erro ao gerar recibo' });
  }
});

// Database initialization
async function initializeDatabase() {
  let client;
  try {
    client = await pool.connect();
    console.log('Connected to database for initialization');

    // Create users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'vendor'))
      )
    `);

    // Create products table
    await client.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        category VARCHAR(50) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        stock INTEGER NOT NULL DEFAULT 0,
        serial_code VARCHAR(100) UNIQUE
      )
    `);

    // Check if serial_code column exists, add if missing
    const columnsResult = await client.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'products' AND table_schema = 'public'
    `);
    const hasSerialCode = columnsResult.rows.some(col => col.column_name === 'serial_code');

    if (!hasSerialCode) {
      await client.query(`
        ALTER TABLE products
        ADD COLUMN serial_code VARCHAR(100) UNIQUE
      `);
      console.log('Added serial_code column to products table');

      // Populate serial_code for existing products
      const productsResult = await client.query('SELECT id FROM products');
      for (const product of productsResult.rows) {
        await client.query(
          'UPDATE products SET serial_code = $1 WHERE id = $2',
          [`SN${String(product.id).padStart(3, '0')}`, product.id]
        );
      }
      console.log('Populated serial_code for existing products');
    }

    // Create sales table
    await client.query(`
      CREATE TABLE IF NOT EXISTS sales (
        id SERIAL PRIMARY KEY,
        vendor_id INTEGER NOT NULL,
        date TIMESTAMP NOT NULL,
        total DECIMAL(10, 2) NOT NULL,
        payment DECIMAL(10, 2) NOT NULL,
        change_amount DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (vendor_id) REFERENCES users(id)
      )
    `);

    // Create sale_items table
    await client.query(`
      CREATE TABLE IF NOT EXISTS sale_items (
        id SERIAL PRIMARY KEY,
        sale_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        product_name VARCHAR(100) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        quantity INTEGER NOT NULL,
        total DECIMAL(10, 2) NOT NULL,
        FOREIGN KEY (sale_id) REFERENCES sales(id) ON DELETE CASCADE
      )
    `);

    // Check if default admin exists
    const adminsResult = await client.query('SELECT * FROM users WHERE role = $1', ['admin']);
    
    // Create default admin if none exists
    if (adminsResult.rows.length === 0) {
      await client.query(`
        INSERT INTO users (username, password, name, role)
        VALUES ($1, $2, $3, $4)
      `, ['admin', 'admin123', 'Administrador', 'admin']);
      console.log('Default admin user created');
    }

    // Add sample products if none exist
    const productsResult = await client.query('SELECT * FROM products');
    if (productsResult.rows.length === 0) {
      const sampleProducts = [
        ['SN001', 'Notebook HP', 'Eletrônicos', 25000.00, 5],
        ['SN002', 'Smartphone Samsung', 'Eletrônicos', 8000.00, 10],
        ['SN003', 'Televisão LG 43"', 'Eletrônicos', 12000.00, 3],
        ['SN004', 'Teclado Sem Fio', 'Acessórios', 1500.00, 15],
        ['SN005', 'Mouse Bluetooth', 'Acessórios', 800.00, 20],
        ['SN006', 'Cadeira de Escritório', 'Móveis', 3500.00, 7],
        ['SN007', 'Mesa de Trabalho', 'Móveis', 4500.00, 4],
        ['SN008', 'Fones de Ouvido', 'Acessórios', 1200.00, 12]
      ];

      for (const product of sampleProducts) {
        await client.query(
          'INSERT INTO products (serial_code, name, category, price, stock) VALUES ($1, $2, $3, $4, $5)',
          product
        );
      }
      console.log('Sample products inserted.');
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  } finally {
    if (client) client.release();
  }
}

// Start the server
async function startServer() {
  try {
    await testConnection();
    await initializeDatabase();
    
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
  }
}

startServer();