// server.js
require('dotenv').config(); // MUST be the very first line
const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid'); // For generating unique IDs

const app = express();
const PORT = process.env.PORT || 3001;

// --- CORS Configuration ---
const allowedOrigins = [
'http://127.0.0.1:5500', // Local development (Live Server default)
  'http://localhost:5500',  // Alternative local development URL
  'https://premeo-store-jj0n0ejg9-omerkhan-ais-projects.vercel.app',// <-- YOUR ACTUAL VERCEL URL
  'https://premeo-store.vercel.app',
  'https://premeo-store.vercel.app/contact.html',
  'https://premeopadel.com'
  
  // Add other domains if needed, e.g., custom domain later:
  // 'https://www.yourstore.com'
];


const corsOptions = {
  origin: function (origin, callback) {
     console.log("--- CORS Debug: Incoming Origin ---"); // Add this line
    console.log("Origin Header Received:", origin);    // Add this line
    console.log("Allowed Origins List:", allowedOrigins); // Add this line
    // Allow requests with no origin (like mobile apps, curl, or server-to-server)
    if (!origin) return callback(null, true);
    // Check if the incoming origin is in our allowed list
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true); // Allow the request
    } else {
      // Block the request if origin is not allowed
      callback(new Error('Not allowed by CORS'));
    }
  }
};
// --- End CORS Configuration ---

// ... other requires ...
const auth = require('./middleware/auth'); // Adjust path if needed
// ... other requires ...
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const AdminUser = require('./models/AdminUser'); // Adjust path if needed
const { generateToken } = require('./utils/auth'); // Adjust path if needed

// Middleware

app.use(cors(corsOptions)); // Use the configured options
app.use(express.json()); // Parse JSON bodies

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGODB_URI, {
  // useNewUrlParser: true, // These options are handled by default in Mongoose 6+
  // useUnifiedTopology: true,
});

// ... rest of your existing code ...

// Add this route in your server.js, preferably near the top
app.get('/api/ping', (req, res) => {
  res.status(200).json({ message: 'Pong! Backend is awake.' });
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log("Connected to MongoDB");
});
const ORDER_STATUSES = ['pending', 'received', 'shipped', 'delivered', 'cancelled', 'paid'];
// --- Mongoose Schema & Model for Orders ---
const orderItemSchema = new mongoose.Schema({
  name: String,
  quality: String,
  quantity: Number,
  price: Number, // Price per item
  itemTotal: Number, // quantity * price
  selectedColor: String // Add the selectedColor field to the schema
});

// Define allowed order statuses (Add this line before orderSchema)


const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  customerInfo: {
    name: String,
    email: String,
    phone: String,
    address: String,
  },
  items: [orderItemSchema],
  subtotal: Number,
  discount: { type: Number, default: 0 },
  shipping: { type: Number, default: 0 },
  tax: { type: Number, default: 0 },
  total: Number,
  paymentMethod: String,
  orderDate: { type: Date, default: Date.now },
  // --- Add/Update the status field ---
  status: {
    type: String,
    enum: ORDER_STATUSES, // Only allow values from the ORDER_STATUSES array
    default: 'pending'   // Default status for new orders
  }
  // --- End status field ---
});

const Order = mongoose.model('Order', orderSchema);

// --- Nodemailer Transporter (Updated for Secure Connection) ---
const transporter = nodemailer.createTransport({ // <-- CORRECTED: Removed 'er'
  host: "smtp.gmail.com", // Explicitly define the host
  port: 465,              // Use port 465 for SSL
  secure: true,          // true for 465, false for other ports like 587 (STARTTLS)
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS // Use App Password for Gmail
  }
});
// --- End of Nodemailer Transporter (Updated) ---

// --- End of Single Order Endpoint ---
// --- API Endpoint for Admin Login ---
app.post('/api/login', async (req, res) => { // <-- Make sure 'async' is here
  const { username, password } = req.body;

  // 1. Basic validation
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
    // 2. Find the user by username
    const user = await AdminUser.findOne({ username: username.trim() });
    if (!user) {
      // Return generic error to avoid revealing if username exists
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // 3. Compare provided password with stored hash
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // 4. Generate JWT token
    const token = generateToken(user._id);

    // 5. Send token back to the client
    res.json({
      message: 'Login successful',
      token: token,
      // user: { id: user._id, username: user.username } // Optional
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login.' });
  }
});
// --- End Login Endpoint ---

// --- Helper Function to Send Email ---
async function sendOrderEmail(orderData) {
  try {
    // --- ENHANCED DEBUGGING BLOCK ---
    console.log("--- DEBUG: sendOrderEmail received orderData ---");
    console.log("Full orderData keys:", Object.keys(orderData || {}));
    if (orderData && Array.isArray(orderData.items)) {
        console.log(`Number of items: ${orderData.items.length}`);
        orderData.items.forEach((item, index) => {
            console.log(`--- Item ${index} ---`);
            console.log(`  Name: '${item.name}'`);
            console.log(`  Type of selectedColor: ${typeof item.selectedColor}`);
            console.log(`  Value of selectedColor:`, item.selectedColor); // Use comma for better inspection of null/undefined
            console.log(`  selectedColor === undefined:`, item.selectedColor === undefined);
            console.log(`  selectedColor === 'undefined':`, item.selectedColor === 'undefined');
            console.log(`  'selectedColor' in item:`, 'selectedColor' in item);
            if (item.selectedColor && typeof item.selectedColor === 'string') {
                console.log(`  Length of selectedColor: ${item.selectedColor.length}`);
                console.log(`  First char code of selectedColor: ${item.selectedColor.charCodeAt(0)}`);
            }
            console.log("--- End Item ---");
        });
    } else {
        console.error("ERROR: orderData.items is missing or not an array. Type:", typeof orderData?.items, "Value:", orderData?.items);
        // Log the entire orderData if items are missing
        console.error("Full orderData received:", JSON.stringify(orderData, null, 2));
    }
    console.log("--- END DEBUG ---");
    // --- END ADDITION ---
    // Format order items for email body
      let itemsList = orderData.items.map(item => {
      // Include selectedColor if it exists and is not null/undefined
      const colorPart = item.selectedColor ? ` (${item.selectedColor})` : '';
      return `<li>${item.name}${colorPart} (${item.quality}) x ${item.quantity} @ PKR ${item.price.toLocaleString()} = PKR ${item.itemTotal.toLocaleString()}</li>`;
    }).join('');

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER, // Send to the store owner/admin
      subject: `New Order Placed - Order ID: ${orderData.orderId}`,
      html: `
        <h2>New Order Received</h2>
        <p><strong>Order ID:</strong> ${orderData.orderId}</p>
        <p><strong>Order Date:</strong> ${new Date(orderData.orderDate).toLocaleString()}</p>
        <p><strong>Customer Name:</strong> ${orderData.customerInfo.name}</p>
        <p><strong>Customer Email:</strong> ${orderData.customerInfo.email}</p>
        <p><strong>Customer Phone:</strong> ${orderData.customerInfo.phone}</p>
        <p><strong>Customer Address:</strong> ${orderData.customerInfo.address}</p>
        <p><strong>Payment Method:</strong> ${orderData.paymentMethod}</p>

        <h3>Order Items:</h3>
        <ul>${itemsList}</ul>

        <table style="width:100%; border-collapse: collapse; border: 1px solid #ddd;">
          <tr><td style="border: 1px solid #ddd; padding: 8px;"><strong>Subtotal:</strong></td><td style="border: 1px solid #ddd; padding: 8px;">PKR ${orderData.subtotal.toLocaleString()}</td></tr>
          ${orderData.discount > 0 ? `<tr><td style="border: 1px solid #ddd; padding: 8px;"><strong>Discount:</strong></td><td style="border: 1px solid #ddd; padding: 8px;">-PKR ${orderData.discount.toLocaleString()}</td></tr>` : ''}
          <tr><td style="border: 1px solid #ddd; padding: 8px;"><strong>Shipping:</strong></td><td style="border: 1px solid #ddd; padding: 8px;">PKR ${orderData.shipping.toLocaleString()}</td></tr>
          <tr><td style="border: 1px solid #ddd; padding: 8px;"><strong>Tax:</strong></td><td style="border: 1px solid #ddd; padding: 8px;">PKR ${orderData.tax.toLocaleString()}</td></tr>
          <tr style="font-weight:bold;"><td style="border: 1px solid #ddd; padding: 8px;"><strong>Total:</strong></td><td style="border: 1px solid #ddd; padding: 8px;">PKR ${orderData.total.toLocaleString()}</td></tr>
        </table>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Order email sent: ' + info.response);
    return true;
  } catch (error) {
    console.error('Error sending order email:', error);
    return false;
  }
};

///////////////////////////////////////////////

// --- API Endpoint to Receive Orders ---
// --- API Endpoint to Receive Orders ---
// --- API Endpoint to Receive Orders ---
app.post('/api/orders', async (req, res) => {
  try {
    // --- ADD THIS DEBUGGING BLOCK AT THE VERY START ---
    console.log("--- DEBUG: Raw req.body received by /api/orders ---");
    console.log("Type of req.body:", typeof req.body);
    console.log("Keys in req.body:", Object.keys(req.body || {}));
    if (req.body && Array.isArray(req.body.items)) {
        console.log(`Number of items in req.body: ${req.body.items.length}`);
        req.body.items.forEach((item, index) => {
            console.log(`--- req.body Item ${index} ---`);
            console.log(`  Name: '${item.name}'`);
            console.log(`  Type of selectedColor: ${typeof item.selectedColor}`);
            console.log(`  Value of selectedColor:`, item.selectedColor); // Comma for null/undefined
            console.log(`  selectedColor === undefined:`, item.selectedColor === undefined);
            console.log(`  'selectedColor' in item:`, 'selectedColor' in item);
            console.log("--- End req.body Item ---");
        });
    } else {
         console.log("req.body.items is missing or not an array. Full req.body:", JSON.stringify(req.body, null, 2));
    }
    console.log("--- END DEBUG: Raw req.body ---");
    // --- END ADDITION ---


    const orderData = req.body; // This should now be the raw data from frontend

    // Generate unique Order ID
    const orderId = `ORD-${uuidv4().substring(0, 8).toUpperCase()}`; // Example: ORD-A1B2C3D4

    // Add Order ID and Date to the data
    orderData.orderId = orderId;
    orderData.orderDate = new Date();

    // Create new Order document
    const newOrder = new Order(orderData);

    // Save to MongoDB
    const savedOrder = await newOrder.save();
    console.log('Order saved to DB:', savedOrder.orderId);

    // --- CONVERT TO PLAIN OBJECT ---
    const plainOrderData = savedOrder.toObject();
    // --- END CONVERSION ---

    // --- ADD THIS DEBUGGING BLOCK AFTER toObject() ---
    console.log("--- DEBUG: plainOrderData after toObject() ---");
    console.log("Type of plainOrderData:", typeof plainOrderData);
    console.log("Keys in plainOrderData:", Object.keys(plainOrderData || {}));
    if (plainOrderData && Array.isArray(plainOrderData.items)) {
        console.log(`Number of items in plainOrderData: ${plainOrderData.items.length}`);
        plainOrderData.items.forEach((item, index) => {
            console.log(`--- plainOrderData Item ${index} ---`);
            console.log(`  Name: '${item.name}'`);
            console.log(`  Type of selectedColor: ${typeof item.selectedColor}`);
            console.log(`  Value of selectedColor:`, item.selectedColor); // Comma for null/undefined
            console.log(`  selectedColor === undefined:`, item.selectedColor === undefined);
            console.log(`  'selectedColor' in item:`, 'selectedColor' in item);
            console.log("--- End plainOrderData Item ---");
        });
    } else {
         console.log("plainOrderData.items is missing or not an array. Full plainOrderData:", JSON.stringify(plainOrderData, null, 2));
    }
    console.log("--- END DEBUG: plainOrderData ---");
    // --- END ADDITION ---


    // Send Email Notification using the PLAIN object
    try {
        await sendOrderEmail(plainOrderData); // <-- Pass the CORRECT plain object
        console.log('Order notification email sent successfully for Order ID:', plainOrderData.orderId);
        // Respond to frontend indicating success (order saved, email sent)
        res.status(201).json({ message: 'Order placed successfully and email sent!', orderId: plainOrderData.orderId });
    } catch (emailError) {
        // The order was saved, but the email failed
        console.error('Order saved, but email notification failed for Order ID:', plainOrderData.orderId, emailError);
        res.status(201).json({ message: 'Order placed successfully (email notification failed)!', orderId: plainOrderData.orderId });
    }

  } catch (error) {
    console.error('Error processing order:', error);
    res.status(500).json({ message: 'Error placing order: ' + error.message });
  }
});
// --- END API Endpoint ---

// --- Basic Endpoint to Fetch Orders (for potential dashboard) ---
 app.get('/api/orders', async (req, res) => {
  try {
    const orders = await Order.find().sort({ orderDate: -1 }); // Get latest orders first
    res.json(orders);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
 });

// - API Endpoint to Search Orders -
app.get('/api/orders/search',async (req, res) => {
  console.log("Search endpoint hit. Query params:", req.query);
  try { // <--- Make sure this 'try' is NOT commented out
    // Get the search query from the URL query parameters (e.g., ?query=omr)
    const searchTerm = req.query.query;
    console.log("Extracted searchTerm:", searchTerm);

    // Check if a search term was provided
    if (!searchTerm || searchTerm.trim() === '') {
      console.log("No search term provided, fetching all orders...");
      const allOrders = await Order.find().sort({ orderDate: -1 });
      console.log(`Found ${allOrders.length} orders.`);
      return res.json(allOrders);
    }

    console.log(`Performing search for term: '${searchTerm}'`);
    const searchRegex = new RegExp(searchTerm, 'i');
    const matchingOrders = await Order.find({
      $or: [
        { orderId: searchRegex },
        { 'customerInfo.name': searchRegex },
        { 'customerInfo.email': searchRegex }
      ]
    }).sort({ orderDate: -1 });

    console.log(`Search for '${searchTerm}' returned ${matchingOrders.length} orders.`);
    res.json(matchingOrders);
  } catch (error) { // <--- This 'catch' must correspond to the 'try' above
    console.error('Error searching orders:', error);
    res.status(500).json({ message: 'Error searching orders', error: error.message });
  }
}); // <--- This closes the 'app.get' route handler function
// - End of Search Orders Endpoint
// --- API Endpoint to Update Order Status ---
app.put('/api/orders/:orderId/status',async (req, res) => {
  try {
    const orderId = req.params.orderId;
    const { status } = req.body; // Get the new status from the request body

    // Validate the provided status
    if (!ORDER_STATUSES.includes(status)) {
      return res.status(400).json({ message: 'Invalid status provided.' });
    }

    // Find the order by its unique orderId field and update the status
    const updatedOrder = await Order.findOneAndUpdate(
      { orderId: orderId },       // Find condition
      { status: status },         // Update data
      { new: true }               // Options: return the updated document
    );

    if (!updatedOrder) {
      return res.status(404).json({ message: 'Order not found.' });
    }

    res.json({ message: 'Order status updated successfully.', order: updatedOrder });
  } catch (error) {
    console.error('Error updating order status:', error);
    // Handle potential errors like CastError for invalid ID format
    if (error.name === 'CastError') {
      return res.status(400).json({ message: 'Invalid order ID format.' });
    }
    res.status(500).json({ message: 'Error updating order status.', error: error.message });
  }
});
// --- End Update Order Status Endpoint ---
// --- API Endpoint to Fetch a Single Order by ID ---
// Route parameter :orderId will capture the value from the URL
app.get('/api/orders/:orderId', async (req, res) => {
  try {
    const orderId = req.params.orderId; // Get the ID from the URL

    // Find the order by its unique orderId field (not the MongoDB _id)
    const order = await Order.findOne({ orderId: orderId });

    if (!order) {
      // If no order found with that ID
      return res.status(404).json({ message: 'Order not found' });
    }

    // If order found, send it back
    res.json(order);
  } catch (error) {
    console.error('Error fetching order details:', error);
    // Handle potential errors like invalid ObjectId format etc.
    if (error.name === 'CastError') {
       return res.status(400).json({ message: 'Invalid order ID format' });
    }
    res.status(500).json({ message: 'Error fetching order details', error: error.message });
  }
});
// --- API Endpoint for Contact Form ---
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // 1. Basic validation
    if (!name || !email || !message) {
      return res.status(400).json({ message: 'Name, email, and message are required.' });
    }

    // 2. Basic email format validation (you can use a more robust library like 'validator' if needed)
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Please provide a valid email address.' });
    }

    // 3. Process the data (send email, save to database, etc.)
    // For now, let's log it and send a confirmation email

    console.log("Received Contact Form Submission:");
    console.log("Name:", name);
    console.log("Email:", email);
    console.log("Subject:", subject || '(No subject)');
    console.log("Message:", message);

    // --- Send Email to Store Owner ---
    const mailOptionsToOwner = {
      from: process.env.EMAIL_USER, // Your store's email
      to: process.env.EMAIL_USER,   // Send to the store owner/admin
      replyTo: email,               // Allow replying directly to the customer
      subject: `Contact Form Submission: ${subject || 'No Subject'}`,
      text: `
        You have received a new message from your website contact form.

        Name: ${name}
        Email: ${email}
        Subject: ${subject || 'N/A'}
        
        Message:
        ${message}
      `,
      html: `
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
        <p><strong>Subject:</strong> ${subject || 'N/A'}</p>
        <h3>Message:</h3>
        <p>${message.replace(/\n/g, '<br>')}</p>
      `
    };

    // --- Optional: Send Confirmation Email to Customer ---
    const mailOptionsToCustomer = {
      from: process.env.EMAIL_USER,
      to: email, // Send to the customer's email
      subject: 'Thank you for contacting PREMEO',
      text: `
        Dear ${name},

        Thank you for reaching out to PREMEO. We have received your message and will get back to you as soon as possible.

        Your message:
        ${message}

        Best regards,
        The PREMEO Team
      `,
      html: `
        <p>Dear ${name},</p>
        <p>Thank you for reaching out to PREMEO. We have received your message and will get back to you as soon as possible.</p>
        <h3>Your Message:</h3>
        <p>${message.replace(/\n/g, '<br>')}</p>
        <p>Best regards,<br>The PREMEO Team</p>
      `
    };

    // Send emails
    await transporter.sendMail(mailOptionsToOwner);
    console.log('Contact form email sent to owner.');
    
    // Optionally send confirmation to customer (uncomment the next 2 lines if desired)
    // await transporter.sendMail(mailOptionsToCustomer);
    // console.log('Confirmation email sent to customer.');

    // 4. Send success response
    res.status(200).json({ message: 'Your message has been sent successfully! We will contact you soon.' });

  } catch (error) {
    console.error('Error processing contact form:', error);
    // Differentiate between Nodemailer errors and others if needed
    if (error.code) {
       console.error('Nodemailer Error Code:', error.code);
    }
    res.status(500).json({ message: 'Failed to send your message. Please try again later.' });
  }
});
// --- End Contact Form Endpoint ---

// --- TEMPORARY: Create Admin User (Remove after first run) ---
// WARNING: Remove this block after creating your admin user!
const createAdminUser = async () => {
  const username = 'admin'; // Change this
  const password = 'securepassword123'; // Change this to a strong password

  try {
    // Check if user already exists
    const existingUser = await AdminUser.findOne({ username });
    if (existingUser) {
      console.log(`Admin user '${username}' already exists.`);
      return;
    }

    // Create new user
    const newUser = new AdminUser({ username, password });
    await newUser.save();
    console.log(`Admin user '${username}' created successfully.`);
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
};

// Call the function (only once)
//createAdminUser(); // Uncomment this line to create the user, then comment it out again!
// --- END TEMPORARY ---
// --- Start Server ---
app.listen(PORT, () => {
  console.log(`Dashboard Backend running on port ${PORT}`);
});
