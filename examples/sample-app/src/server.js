const port = process.env.PORT || 3000;
const databaseUrl = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;
const stripeKey = process.env.STRIPE_SECRET_KEY;
const { SMTP_HOST, SMTP_PORT = "587" } = process.env;

console.log(`listening on ${port}`, Boolean(databaseUrl && jwtSecret && stripeKey), SMTP_HOST, SMTP_PORT);
