package db

import (
	"fmt"
	"hash/fnv"
	"math/rand"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/persona"
)

// Table is one fake table. Values are text (the decoy reports every column as text).
type Table struct {
	Name    string
	Columns []string
	Rows    [][]string
}

// Dataset is the fake "orders" database of the persona's company, deterministic from the persona seed.
// Every person, card and hash here is generated; none is real.
type Dataset struct {
	Persona persona.Persona
	Tables  map[string]*Table
	Order   []string
}

var (
	cities   = []string{"Mumbai", "Pune", "Bengaluru", "Chennai", "Hyderabad", "Delhi", "Ahmedabad", "Kolkata"}
	clientCo = []string{"Apex Retail", "Sunrise Pharma", "Coastal Foods", "Metro Textiles", "Vertex Auto Parts",
		"Bluewave Electronics", "Greenleaf Organics", "Northstar Furniture", "Prime Steel", "Orbit Appliances"}
	firstName = []string{"Rahul", "Priya", "Amit", "Neha", "Karan", "Sneha", "Vivek", "Anjali", "Rohit", "Pooja"}
	lastName  = []string{"Verma", "Sharma", "Patil", "Reddy", "Iyer", "Joshi", "Kulkarni", "Menon", "Bose", "Shah"}
	statuses  = []string{"delivered", "delivered", "in_transit", "delivered", "pending", "cancelled"}
	methods   = []string{"card", "upi", "netbanking", "card", "upi"}
)

func NewDataset(p persona.Persona) *Dataset {
	h := fnv.New64a()
	h.Write([]byte(p.Seed + p.Company))
	r := rand.New(rand.NewSource(int64(h.Sum64())))
	domain := p.Domain
	if domain == "" {
		domain = "example.internal"
	}
	mail := strings.TrimSuffix(domain, ".internal") + ".in"
	pick := func(xs []string) string { return xs[r.Intn(len(xs))] }
	base := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)

	customers := &Table{Name: "customers", Columns: []string{"id", "company", "contact_name", "email", "phone", "city", "created_at"}}
	for i := 1; i <= 24; i++ {
		co := clientCo[(i-1)%len(clientCo)]
		if i > len(clientCo) {
			co += fmt.Sprintf(" %s", pick(cities))
		}
		fn, ln := pick(firstName), pick(lastName)
		slug := strings.ToLower(strings.ReplaceAll(strings.Fields(co)[0], " ", ""))
		customers.Rows = append(customers.Rows, []string{fmt.Sprint(i), co, fn + " " + ln,
			fmt.Sprintf("%s.%s@%s-corp.in", strings.ToLower(fn), strings.ToLower(ln), slug),
			fmt.Sprintf("+91 9%09d", r.Intn(1_000_000_000)), pick(cities), base.Add(time.Duration(i*61) * time.Hour).Format("2006-01-02 15:04:05")})
	}

	orders := &Table{Name: "orders", Columns: []string{"id", "customer_id", "origin", "destination", "amount_inr", "status", "created_at"}}
	payments := &Table{Name: "payments", Columns: []string{"id", "order_id", "method", "card_last4", "upi_ref", "amount_inr", "status"}}
	for i := 1; i <= 60; i++ {
		amt := fmt.Sprintf("%d.%02d", 4000+r.Intn(180000), r.Intn(100))
		st := pick(statuses)
		orders.Rows = append(orders.Rows, []string{fmt.Sprint(1000 + i), fmt.Sprint(1 + r.Intn(24)), pick(cities), pick(cities),
			amt, st, base.Add(time.Duration(i*29) * time.Hour).Format("2006-01-02 15:04:05")})
		m := pick(methods)
		last4, upi := "", ""
		if m == "card" {
			last4 = fmt.Sprintf("%04d", r.Intn(10000))
		} else if m == "upi" {
			upi = fmt.Sprintf("UPI%012d", r.Int63n(1_000_000_000_000))
		}
		pst := "captured"
		if st == "cancelled" {
			pst = "refunded"
		} else if st == "pending" {
			pst = "authorized"
		}
		payments.Rows = append(payments.Rows, []string{fmt.Sprint(5000 + i), fmt.Sprint(1000 + i), m, last4, upi, amt, pst})
	}

	staff := &Table{Name: "staff_users", Columns: []string{"id", "username", "email", "role", "password_hash", "last_login"}}
	roles := []string{"admin", "ops", "ops", "finance", "support"}
	users := p.Users
	for i, u := range users {
		if i >= len(roles) {
			break
		}
		staff.Rows = append(staff.Rows, []string{fmt.Sprint(i + 1), u.Name, u.Name + "@" + mail, roles[i],
			"$2b$12$" + randStr(r, 53), base.Add(time.Duration(2000+i*13) * time.Hour).Format("2006-01-02 15:04:05")})
	}
	staff.Rows = append(staff.Rows, []string{fmt.Sprint(len(staff.Rows) + 1), "svc_backup", "svc-backup@" + mail, "service",
		"$2b$12$" + randStr(r, 53), base.Add(2100 * time.Hour).Format("2006-01-02 15:04:05")})

	d := &Dataset{Persona: p, Tables: map[string]*Table{}, Order: []string{"customers", "orders", "payments", "staff_users"}}
	for _, t := range []*Table{customers, orders, payments, staff} {
		d.Tables[t.Name] = t
	}
	return d
}

func randStr(r *rand.Rand, n int) string {
	const a = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = a[r.Intn(len(a))]
	}
	return string(b)
}
