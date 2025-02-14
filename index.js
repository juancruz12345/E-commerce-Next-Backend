import express from 'express'
import dotenv from 'dotenv'
import { createClient } from '@libsql/client'
import { MercadoPagoConfig,Preference } from 'mercadopago';
import { UserRepository } from './user-repository.js';
import jwt from 'jsonwebtoken'
import cookieParser from 'cookie-parser';
import cors from 'cors'


dotenv.config()

if (!process.env.DB_URL || !process.env.DB_TOKEN || !process.env.SECRET_KEY) {
  throw new Error("Missing environment variables");
}


const app = express()


const ACCEPTED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5000',

]

app.use(cors({credentials: true ,
  origin: ACCEPTED_ORIGINS
  
}));

app.use(express.json())
app.use(cookieParser())

const PORT = process.env.PORT || 5000;

const db = createClient({
    url:process.env.DB_URL,
    authToken: process.env.DB_TOKEN
})




app.use((req, res, next) => {
  const accessToken = req.cookies.acces_token;
  const refreshToken = req.cookies.refresh_token;
  const isProduction = process.env.NODE_ENV === 'production';
  req.session = { user: null };

  try {
    if (accessToken) {
      // Verificar el access token
      const data = jwt.verify(accessToken, process.env.SECRET_KEY);
      req.session.user = data; 
    } else if (refreshToken) {
      // Intentar refrescar el access token usando el refresh token
      try {
        const refreshData = jwt.verify(refreshToken, process.env.REFRESH_SECRET_KEY);
        
        // Generar un nuevo access token
        const newAccessToken = jwt.sign(
          { id: refreshData.id, username: refreshData.username },
          process.env.SECRET_KEY,
          { expiresIn: '1h' }
        );

        // Establecer la nueva cookie de access token
        res.cookie('acces_token', newAccessToken, {
            httpOnly: true,
            secure: isProduction,  // Solo HTTPS en producción
            sameSite: isProduction ? 'None' : 'Lax', // 'None' si es producción, 'Lax' para desarrollo
            maxAge: 1000 * 60 * 60  // 1 hora
        
        });

        req.session.user = { id: refreshData.id, username: refreshData.username };
      } catch (refreshErr) {
        console.error('Error al refrescar el token:', refreshErr);
        return res.status(403).send('Invalid refresh token');
      }
    }
  } catch (err) {
    console.error('Error de autenticación:', err.message);
    return res.status(401).send('Invalid access token');
  }

  next();
});



app.get('/', (req, res) => {
    const {user} = req.session
    res.json(user)
  })






///USER///////////////////
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await UserRepository.login({ username, password });

        const accesToken = jwt.sign(
            { id: user.id, username: user.username },
            process.env.SECRET_KEY,
            { expiresIn: '1h' }
        );

        const refreshToken = jwt.sign(
            { id: user.id, username: user.username },
            process.env.REFRESH_SECRET_KEY,
            { expiresIn: '7d' }
        );

        const isProduction = process.env.NODE_ENV === 'production';

        res.cookie('acces_token', accesToken, {
            httpOnly: true,
            secure: isProduction,  // Solo HTTPS en producción
            sameSite: isProduction ? 'None' : 'Lax', // 'None' si es producción, 'Lax' para desarrollo
            maxAge: 1000 * 60 * 60  // 1 hora
        });

        res.cookie('refresh_token', refreshToken, {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'None' : 'Lax',
            maxAge: 1000 * 60 * 60 * 24 * 7 // 7 días
        });

        res.send({ user, accesToken, refreshToken });

    } catch (e) {
        res.status(401).send(e.message);
    }
});

app.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  try {
      const result = await UserRepository.create({ username, password, email });
      console.log(result)
    res.send({result})
      // No necesitas enviar una respuesta aquí, ya que `create` ya lo hace
  } catch (e) {
      // Si hay un error inesperado, devuelve un JSON
      res.status(500).json({ error: "Error interno del servidor: " + e.message });
  }
});



  app.post('/refresh-token', (req, res) => {
    const isProduction = process.env.NODE_ENV === 'production';
    const { refresh_token } = req.cookies
    if (!refresh_token) return res.status(403).send('Refresh token not provided')
  
    try {
      const data = jwt.verify(refresh_token, process.env.REFRESH_SECRET_KEY)
      const newAccessToken = jwt.sign(
        { id: data.id, username: data.username },
        process.env.SECRET_KEY,
        { expiresIn: '1h' }
      )
  
      res.cookie('access_token', newAccessToken, {
        httpOnly: true,
        secure: isProduction,  // Solo HTTPS en producción
        sameSite: isProduction ? 'None' : 'Lax', // 'None' si es producción, 'Lax' para desarrollo
        maxAge: 1000 * 60 * 60  // 1 hora
      })
      .send({ accessToken: newAccessToken })
    } catch (e) {
      res.status(403).send('Invalid refresh token')
    }
  })



  app.get('orders/:id', async(req,res)=>{

    const {user_id} = req.params

    try{

      const orders = await db.execute({
        sql:'SELECT * FROM orders WHERE user_id = :user_id',
        args:[user_id]
      })

      res.send(orders)

    }catch(e){
      res.status(403).send('Error whit order: ', e)
    }
  })






  
  // Ruta para verificar el usuario
  app.get("/verify/:email", async (req, res) => {
      const { email } = req.params;
  
      try {
          await db.execute("UPDATE users SET verificado = 1 WHERE email = ?", [email]);
          res.json({ success: true, message: "Usuario verificado correctamente" });
      } catch (error) {
          console.error("Error al verificar el usuario:", error);
          res.status(500).json({ success: false, error: "Error en el servidor" });
      }
  });















  app.post('/create-paypal-order', async (req, res) => {
    const { amount, user_id, items, payment_method = "paypal" } = req.body; 
    
    try {
      // Obtener Access Token de PayPal
      const tokenResponse = await fetch('http://localhost:5000/get-paypal-token', {
        method: 'POST',
      });
      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.access_token;
  
      // Crear la orden en PayPal
      const order = {
        intent: 'CAPTURE',
        purchase_units: [{
          amount: {
            currency_code: 'USD',
            value: amount,
          }
        }]
      };
  
      const response = await fetch('https://api-m.sandbox.paypal.com/v2/checkout/orders', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body: JSON.stringify(order),
      });
  
      const data = await response.json();
  
      if (!data.id) {
        return res.status(400).json({ error: "No se pudo crear la orden en PayPal" });
      }
  
      const order_id = data.id; // ID de la orden en PayPal
  
      // Guardar la orden en la base de datos
      await db.execute(
        `INSERT INTO orders (order_id, user_id, status, total, payment_method) VALUES (?, ?, ?, ?, ?)`,
        [order_id, user_id, "PENDING", amount, payment_method]
      );
  
      // Guardar los ítems de la orden
      for (const item of items) {
        await db.execute(
          `INSERT INTO order_items (order_id, product_name, quantity, price) VALUES (?, ?, ?, ?)`,
          [order_id, item.name, item.quantity, item.price]
        );
      }
  
      res.json({ success: true, order_id, data });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  

  app.post('/capture-paypal-order', async (req, res) => {
    const { orderID } = req.body;
  
    try {
      // Obtener Access Token de PayPal
      const tokenResponse = await fetch('http://localhost:5000/get-paypal-token', {
        method: 'POST',
      });
      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.access_token;
  
      // Capturar el pago
      const response = await fetch(`https://api-m.sandbox.paypal.com/v2/checkout/orders/${orderID}/capture`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${accessToken}`
        }
      });
  
      const data = await response.json();
  
      // Si el pago fue exitoso
      if (data.status === "COMPLETED") {
        await db.execute(
          `UPDATE orders SET status = ? WHERE order_id = ?`,
          ["COMPLETED", orderID]
        );
  
        return res.json({ success: true, message: "Pago exitoso", orderID });
      } else {
        return res.status(400).json({ success: false, message: "No se pudo capturar el pago" });
      }
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  




  app.post('/get-paypal-token', async (req, res) => {
    const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64');
  
    try {
      const response = await fetch('https://api-m.sandbox.paypal.com/v1/oauth2/token', {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: 'grant_type=client_credentials',
      });
  
      if (!response.ok) {
        throw new Error('Failed to fetch PayPal access token');
      }
  
      const data = await response.json();
      res.json(data); // Enviamos el token al frontend o a quien lo necesite
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  


  app.post('/logout', (req,res)=>{
    res.clearCookie('acces_token')
    res.clearCookie('refresh_token')
    .json({message:'logout succesful'})
})

 
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  }).on('error', (err) => {
    console.error('Server failed to start:', err);
  });

  export default app;
