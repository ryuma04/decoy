// Seeds one Aetees lab database (run from inside .lab/aetees so @prisma/client resolves).
//   node seed.mjs real   -> the catalogue only (the "real" shop for the demo)
//   node seed.mjs decoy  -> the same catalogue + synthetic customers and orders for the honeypot clone
// Decoy env: CANARY_INVOICE_URL (honeytoken link planted in an order note), BREADCRUMB_PATH.
// Every person and order here is generated; none is a real customer.
import { PrismaClient } from '@prisma/client';

const mode = process.argv[2] || 'real';
const prisma = new PrismaClient();

const catalogue = [
  { cat: 'Cakes', items: [
    ['Chocolate Truffle Cake', 'Dark chocolate sponge layered with silky truffle ganache.', 850, '/hero-cakes.jpg', true, true],
    ['Red Velvet Cake', 'Cocoa-kissed red velvet with cream cheese frosting.', 900, '/hero-cakes.jpg', true, false],
    ['Pineapple Fresh Cream Cake', 'Light vanilla sponge, fresh cream and pineapple.', 700, '/hero-cakes.jpg', false, false],
    ['Belgian Chocolate Mousse Cake', 'Rich mousse on a chocolate biscuit base.', 1100, '/hero-cakes.jpg', false, true],
  ] },
  { cat: 'Cheesecakes', items: [
    ['Blueberry Cheesecake', 'Baked New York cheesecake with blueberry compote.', 1200, '/cheesecake.png', true, true],
    ['Biscoff Cheesecake', 'Creamy cheesecake with a Lotus Biscoff crust.', 1250, '/cheesecake.png', false, true],
  ] },
  { cat: 'Cookies', items: [
    ['Choco Chip Cookies (6)', 'Chewy brown-butter cookies loaded with chocolate.', 320, '/choco-chip.png', true, false],
    ['Double Chocolate Cookies (6)', 'Fudgy cocoa cookies with dark chocolate chunks.', 360, '/choco-chip.png', false, false],
  ] },
  { cat: 'Brownies', items: [
    ['Classic Fudge Brownie Box', 'Six dense fudge brownies.', 450, '/choco-chip.png', false, true],
    ['Walnut Brownie Box', 'Six brownies with toasted walnuts.', 480, '/choco-chip.png', false, false],
  ] },
];
const sizes = [['SIZE:::Half kg', 0], ['SIZE:::1 kg', 650], ['SIZE:::1.5 kg', 1200]];

const first = ['Aarav', 'Riya', 'Kabir', 'Ananya', 'Vihaan', 'Isha', 'Arjun', 'Meera', 'Rohan', 'Sana', 'Dev', 'Nisha',
  'Kunal', 'Pooja', 'Aditya', 'Tara', 'Yash', 'Neha', 'Siddharth', 'Kavya'];
const last = ['Sharma', 'Kapoor', 'Mehta', 'Iyer', 'Shah', 'Nair', 'Desai', 'Rao', 'Patel', 'Joshi', 'Menon', 'Gupta'];
const areas = ['Andheri West', 'Bandra West', 'Powai', 'Juhu', 'Malad West', 'Goregaon East', 'Chembur', 'Vile Parle East'];
const pick = (a, i) => a[i % a.length];

async function catalogueSeed() {
  const products = [];
  let sort = 0;
  const eggless = await prisma.filterTag.create({ data: { name: 'Eggless' } });
  const best = await prisma.filterTag.create({ data: { name: 'Bestseller' } });
  for (const [ci, group] of catalogue.entries()) {
    const category = await prisma.category.create({ data: { name: group.cat, sortOrder: ci } });
    for (const [name, description, price, imageUrl, isFeatured, isBestSeller] of group.items) {
      const p = await prisma.product.create({
        data: {
          name, description, price, imageUrl, isFeatured, isBestSeller, categoryId: category.id, sortOrder: sort++,
          hasEggless: true, hasEgg: true,
          filters: { connect: [{ id: eggless.id }, ...(isBestSeller ? [{ id: best.id }] : [])] },
          options: group.cat === 'Cakes' || group.cat === 'Cheesecakes'
            ? { create: sizes.map(([n, extra]) => ({ name: n, extraPrice: extra })) } : undefined,
        },
      });
      products.push(p);
    }
  }
  return products;
}

async function decoySeed(products) {
  const canary = process.env.CANARY_INVOICE_URL || '';
  const crumb = process.env.BREADCRUMB_PATH || '/backup/';
  const statuses = ['PAID', 'PAID', 'PAID', 'DELIVERED', 'DELIVERED', 'SHIPPED', 'PENDING', 'CANCELLED'];
  const now = Date.now();
  for (let i = 0; i < 36; i++) {
    const fn = pick(first, i * 7 + 3), ln = pick(last, i * 5 + 1);
    const user = await prisma.user.create({
      data: {
        firstName: fn, lastName: ln,
        email: `${fn}.${ln}${1000 + ((i * 7919) % 9000)}@gmail.com`.toLowerCase(),
        phone: `9${String(100000000 + ((i * 48271) % 899999999)).padStart(9, '0')}`,
        addresses: { create: { addressLine1: `${10 + i}, ${pick(['Sea Breeze', 'Palm Grove', 'Sunrise', 'Lakeview'], i)} CHS`,
          addressLine2: pick(areas, i), city: 'Mumbai', postalCode: `4000${String(50 + (i % 49)).padStart(2, '0')}` } },
      },
    });
    const orders = 1 + (i % 3);
    for (let k = 0; k < orders; k++) {
      const p = products[(i + k * 3) % products.length];
      const qty = 1 + ((i + k) % 2);
      const created = new Date(now - ((i * 3 + k) * 26 + 5) * 3600 * 1000);
      let notes = pick(['Please write "Happy Birthday Mom"', 'Less sugar if possible', 'Deliver after 6 pm', '', '', 'Gate code 4512'], i + k);
      if (i === 4 && k === 0) notes = `Corporate order — invoice copy: ${canary}`;
      if (i === 11 && k === 0) notes = `Staff note: last DB export moved to ${crumb} (remove before audit)`;
      await prisma.order.create({
        data: {
          userId: user.id, totalAmount: Number(p.price) * qty, status: pick(statuses, i + k),
          razorpayOrderId: `order_${(now - i * 997 - k).toString(36).toUpperCase()}${i}${k}`,
          deliveryDate: new Date(created.getTime() + 2 * 86400 * 1000), notes, createdAt: created,
          items: { create: [{ productId: p.id, quantity: qty, price: p.price, size: p.name.includes('Cake') ? '1 kg' : null }] },
        },
      });
    }
  }
}

const products = await catalogueSeed();
if (mode === 'decoy') await decoySeed(products);
console.log(`seeded ${mode}: ${products.length} products${mode === 'decoy' ? ' + synthetic customers/orders' : ''}`);
await prisma.$disconnect();
