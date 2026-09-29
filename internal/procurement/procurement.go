// Package procurement is a mock procurement MCP server with in-memory data.
package procurement

import (
	"context"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Supplier struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Country      string `json:"country"`
	ContactEmail string `json:"contactEmail"`
	BankAccount  string `json:"bankAccount"`
	TaxID        string `json:"taxId"`
}

type PurchaseOrder struct {
	ID          string  `json:"id"`
	Supplier    string  `json:"supplier"`
	Amount      float64 `json:"amount"`
	Status      string  `json:"status"`
	Description string  `json:"description,omitempty"`
}

type store struct {
	mu        sync.Mutex
	suppliers map[string]Supplier
	orders    []PurchaseOrder
	next      int
}

func seed() *store {
	return &store{
		suppliers: map[string]Supplier{
			"SUP-001": {"SUP-001", "Acme Industrial Supply", "US", "acme@try-solo.io", "004815162342", "94-3175520"},
			"SUP-002": {"SUP-002", "Globex Logistics", "DE", "globex@try-solo.io", "7730291846", "36-4821957"},
			"SUP-003": {"SUP-003", "Initech Office Products", "US", "initech@try-solo.io", "551903377120", "27-6603145"},
		},
		orders: []PurchaseOrder{
			{ID: "PO-1001", Supplier: "SUP-001", Amount: 4200, Status: "approved"},
			{ID: "PO-1002", Supplier: "SUP-002", Amount: 18750, Status: "pending_approval"},
			{ID: "PO-1003", Supplier: "SUP-003", Amount: 960, Status: "approved"},
		},
		next: 1004,
	}
}

type idIn struct {
	ID string `json:"id" jsonschema:"supplier ID, for example SUP-001"`
}

type ordersOut struct {
	Orders []PurchaseOrder `json:"orders"`
}

type createIn struct {
	Supplier    string  `json:"supplier" jsonschema:"supplier ID, for example SUP-001"`
	Amount      float64 `json:"amount" jsonschema:"order total in USD"`
	Description string  `json:"description,omitempty" jsonschema:"what is being purchased"`
}

type emailIn struct {
	To      string `json:"to" jsonschema:"recipient email address"`
	Subject string `json:"subject" jsonschema:"email subject"`
	Body    string `json:"body" jsonschema:"email body"`
}

type emailOut struct {
	Status string `json:"status"`
	To     string `json:"to"`
}

type deleteOut struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// NewServer returns an MCP server with fresh seed data.
func NewServer() *mcp.Server {
	st := seed()
	s := mcp.NewServer(&mcp.Implementation{Name: "procurement-mcp", Version: "0.1.1"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "get_supplier", Description: "Look up a supplier record, including payment details"}, st.getSupplier)
	mcp.AddTool(s, &mcp.Tool{Name: "list_purchase_orders", Description: "List purchase orders"}, st.listOrders)
	mcp.AddTool(s, &mcp.Tool{Name: "create_purchase_order", Description: "Create a purchase order for a supplier"}, st.createOrder)
	mcp.AddTool(s, &mcp.Tool{Name: "send_supplier_email", Description: "Send an email to a supplier contact"}, st.sendEmail)
	mcp.AddTool(s, &mcp.Tool{Name: "delete_supplier", Description: "Delete a supplier record"}, st.deleteSupplier)
	return s
}

func (st *store) getSupplier(_ context.Context, _ *mcp.CallToolRequest, in idIn) (*mcp.CallToolResult, Supplier, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.suppliers[in.ID]
	if !ok {
		return nil, Supplier{}, fmt.Errorf("supplier %s not found", in.ID)
	}
	return nil, s, nil
}

func (st *store) listOrders(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ordersOut, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return nil, ordersOut{Orders: append([]PurchaseOrder(nil), st.orders...)}, nil
}

func (st *store) createOrder(_ context.Context, _ *mcp.CallToolRequest, in createIn) (*mcp.CallToolResult, PurchaseOrder, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.suppliers[in.Supplier]; !ok {
		return nil, PurchaseOrder{}, fmt.Errorf("supplier %s not found", in.Supplier)
	}
	if in.Amount <= 0 {
		return nil, PurchaseOrder{}, fmt.Errorf("amount must be positive")
	}
	po := PurchaseOrder{ID: fmt.Sprintf("PO-%d", st.next), Supplier: in.Supplier, Amount: in.Amount, Status: "created", Description: in.Description}
	st.next++
	st.orders = append(st.orders, po)
	return nil, po, nil
}

func (st *store) sendEmail(_ context.Context, _ *mcp.CallToolRequest, in emailIn) (*mcp.CallToolResult, emailOut, error) {
	return nil, emailOut{Status: "queued", To: in.To}, nil
}

func (st *store) deleteSupplier(_ context.Context, _ *mcp.CallToolRequest, in idIn) (*mcp.CallToolResult, deleteOut, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.suppliers[in.ID]; !ok {
		return nil, deleteOut{}, fmt.Errorf("supplier %s not found", in.ID)
	}
	delete(st.suppliers, in.ID)
	return nil, deleteOut{ID: in.ID, Deleted: true}, nil
}
