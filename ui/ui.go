package ui

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gchaincl/httplab"
	"github.com/gchaincl/httplab/security"
	"github.com/jroimartin/gocui"
)

const (
	STATUS_VIEW      = "status"
	DELAY_VIEW       = "delay"
	HEADERS_VIEW     = "headers"
	BODY_VIEW        = "body"
	REQUEST_VIEW     = "request"
	INFO_VIEW        = "info"
	BODYFILE_VIEW    = "bodyfile"
	SAVE_VIEW        = "save"
	RESPONSES_VIEW   = "responses"
	BINDINGS_VIEW    = "bindings"
	FILE_DIALOG_VIEW = "file-dialog"
)

var cicleable = []string{
	STATUS_VIEW,
	DELAY_VIEW,
	HEADERS_VIEW,
	BODY_VIEW,
	REQUEST_VIEW,
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Cursors stores the cursor position for a specific view
// this is used to restore mouse position when click is detected
type Cursors map[string]struct{ x, y int }

func NewCursors() Cursors {
	return make(Cursors)
}

func (c Cursors) Restore(view *gocui.View) error {
	return view.SetCursor(c.Get(view.Name()))
}

func (c Cursors) Get(view string) (int, int) {
	if v, ok := c[view]; ok {
		return v.x, v.y
	}
	return 0, 0
}

func (c Cursors) Set(view string, x, y int) {
	c[view] = struct{ x, y int }{x, y}
}

type UI struct {
	resp                *httplab.Response
	responses           *httplab.ResponsesList
	infoTimer           *time.Timer
	viewIndex           int
	currentPopup        string
	configPath          string
	hideResponseBuilder bool
	cursors             Cursors
	guard               *security.Guard

	reqLock        sync.Mutex
	requests       []*httplab.Capture
	currentRequest int

	// Short-term reveal authorization: only the request identified by
	// revealID is shown unmasked, and only until revealUntil.
	revealID    string
	revealUntil time.Time
	revealTimer *time.Timer
}

func New(configPath string, guard *security.Guard) *UI {
	return &UI{
		resp: &httplab.Response{
			Status: 200,
			Headers: http.Header{
				"X-Server": []string{"HTTPLab"},
			},
			Body: httplab.Body{
				Mode:  httplab.BodyInput,
				Input: []byte("Hello, World"),
			},
		},
		responses:  httplab.NewResponsesList(),
		configPath: configPath,
		cursors:    NewCursors(),
		guard:      guard,
	}
}

func (ui *UI) Init(g *gocui.Gui) (chan<- error, error) {
	g.Cursor = true
	g.Highlight = true
	g.SelFgColor = gocui.ColorGreen
	g.Mouse = true

	g.SetManager(ui)
	if err := Bindings.Apply(ui, g); err != nil {
		return nil, err
	}

	errCh := make(chan error)
	go func() {
		err := <-errCh
		g.Execute(func(g *gocui.Gui) error {
			return err
		})
	}()

	for _, view := range cicleable {
		fn := func(g *gocui.Gui, v *gocui.View) error {
			cx, cy := v.Cursor()
			line, err := v.Line(cy)
			if err != nil {
				ui.cursors.Restore(v)
				ui.setView(g, v.Name())
				return nil
			}

			if cx > len(line) {
				v.SetCursor(len(line), cy)
				ui.cursors.Set(v.Name(), len(line), cy)
			}

			ui.setView(g, v.Name())
			return nil
		}

		if err := g.SetKeybinding(view, gocui.MouseLeft, gocui.ModNone, fn); err != nil {
			return nil, err
		}

		if err := g.SetKeybinding(view, gocui.MouseRelease, gocui.ModNone, fn); err != nil {
			return nil, err
		}
	}

	return errCh, nil
}

func (ui *UI) AddRequest(g *gocui.Gui, req *http.Request) error {
	ui.reqLock.Lock()
	defer ui.reqLock.Unlock()

	ui.Info(g, "%s", "New Request from "+req.Host)

	// Collection boundary: the request is rendered once, classified and
	// tagged with sensitive spans here; downstream code only ever sees the
	// Capture.
	captured, err := httplab.CaptureRequest(req, ui.guard.Policy)
	if err != nil {
		return err
	}
	captured.ID = fmt.Sprintf("req-%d", len(ui.requests)+1)

	if ui.currentRequest == len(ui.requests)-1 {
		ui.currentRequest = ui.currentRequest + 1
	}

	ui.requests = append(ui.requests, captured)

	// Persist an envelope-encrypted copy into the managed capture store.
	// Failures never block request handling.
	if ui.guard.Store != nil {
		if _, err := ui.guard.Store.Persist(captured.Record()); err != nil {
			ui.Info(g, "%s", "encrypted capture failed: "+err.Error())
		}
	}

	return ui.updateRequest(g)
}

func (ui *UI) updateRequest(g *gocui.Gui) error {
	captured := ui.requests[ui.currentRequest]

	view, err := g.View(REQUEST_VIEW)
	if err != nil {
		return err
	}

	revealed := ui.isRevealed(captured)
	title := fmt.Sprintf("Request (%d/%d)", ui.currentRequest+1, len(ui.requests))
	if masked := captured.MaskedCount(); masked > 0 {
		if revealed {
			title += fmt.Sprintf(" %d REVEALED until %s", masked, ui.revealUntil.Format("15:04:05"))
		} else {
			title += fmt.Sprintf(" %d masked", masked)
		}
	}
	view.Title = title
	return ui.Display(g, REQUEST_VIEW, captured.Render(!revealed))
}

// isRevealed reports whether the capture currently holds a valid short-term
// reveal grant.
func (ui *UI) isRevealed(c *httplab.Capture) bool {
	return ui.revealID != "" && c.ID == ui.revealID && ui.guard.Now().Before(ui.revealUntil)
}

// clearReveal drops any active grant and cancels its auto re-mask timer.
// Callers must hold ui.reqLock.
func (ui *UI) clearReveal() {
	ui.revealID = ""
	ui.revealUntil = time.Time{}
	if ui.revealTimer != nil {
		ui.revealTimer.Stop()
		ui.revealTimer = nil
	}
}

// revealCurrent grants a short, audited window in which the sensitive
// values of the *current* request are displayed. The window expires
// automatically and is revoked as soon as the user navigates away.
func (ui *UI) revealCurrent(g *gocui.Gui) error {
	ui.reqLock.Lock()
	defer ui.reqLock.Unlock()

	if len(ui.requests) == 0 {
		ui.Info(g, "%s", "No Requests to reveal")
		return nil
	}

	captured := ui.requests[ui.currentRequest]
	sensitive := captured.SensitiveSpans()
	if len(security.MergeSpans(sensitive, len(captured.Plain))) == 0 {
		ui.Info(g, "%s", "No sensitive fields classified in this request")
		return nil
	}

	ttl := ui.guard.RevealTTL()
	ui.revealID = captured.ID
	ui.revealUntil = ui.guard.Now().Add(ttl)

	ui.guard.RecordEvent(security.Event{
		Action:     security.AuditReveal,
		RequestID:  captured.ID,
		Method:     captured.Method,
		URI:        captured.URI,
		RemoteAddr: captured.RemoteAddr,
		Spans:      ui.guard.Snapshots(captured.Plain, sensitive),
	})

	if err := ui.updateRequest(g); err != nil {
		return err
	}
	ui.Info(g, "Sensitive values revealed for %s (audit logged)", ttl)

	if ui.revealTimer != nil {
		ui.revealTimer.Stop()
	}
	ui.revealTimer = time.AfterFunc(ttl, func() {
		g.Execute(func(g *gocui.Gui) error {
			ui.reqLock.Lock()
			defer ui.reqLock.Unlock()
			if ui.revealID == "" {
				return nil
			}
			ui.clearReveal()
			if err := ui.updateRequest(g); err != nil {
				return err
			}
			ui.Info(g, "%s", "Reveal window expired - sensitive values masked again")
			return nil
		})
	})
	return nil
}

func (ui *UI) resetRequests(g *gocui.Gui) error {
	ui.reqLock.Lock()
	defer ui.reqLock.Unlock()
	ui.requests = nil
	ui.currentRequest = 0
	ui.clearReveal()

	v, err := g.View(REQUEST_VIEW)
	if err != nil {
		return err
	}

	v.Title = "Request"
	v.Clear()
	ui.Info(g, "%s", "Requests cleared")
	return nil
}

func (ui *UI) Layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	var splitX, splitY *Split
	if ui.hideResponseBuilder {
		splitX = NewSplit(maxX).Fixed(maxX - 1)
	} else {
		splitX = NewSplit(maxX).Relative(70)
	}
	splitY = NewSplit(maxY).Fixed(maxY - 2)

	if v, err := g.SetView(REQUEST_VIEW, 0, 0, splitX.Next(), splitY.Next()); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Request"
		v.Editable = true
		v.Editor = newEditor(ui, g, &motionEditor{})
	}

	if err := ui.setResponseView(g, splitX.Current(), 0, maxX-1, splitY.Current()); err != nil {
		return err
	}

	if v, err := g.SetView(INFO_VIEW, -1, splitY.Current(), maxX-1, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Frame = false
	}

	if v := g.CurrentView(); v == nil {
		_, err := g.SetCurrentView(STATUS_VIEW)
		if err != gocui.ErrUnknownView {
			return err
		}
	}

	return nil
}

func (ui *UI) setResponseView(g *gocui.Gui, x0, y0, x1, y1 int) error {
	if ui.hideResponseBuilder {
		g.DeleteView(STATUS_VIEW)
		g.DeleteView(DELAY_VIEW)
		g.DeleteView(HEADERS_VIEW)
		g.DeleteView(BODY_VIEW)
		return nil
	}

	split := NewSplit(y1).Fixed(2, 2).Relative(40)
	if v, err := g.SetView(STATUS_VIEW, x0, y0, x1, split.Next()); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}

		v.Title = "Status"
		v.Editable = true
		v.Editor = newEditor(ui, g, &numberEditor{3})
		fmt.Fprintf(v, "%d", ui.resp.Status)
	}

	if v, err := g.SetView(DELAY_VIEW, x0, split.Current(), x1, split.Next()); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}

		v.Title = "Delay (ms) "
		v.Editable = true
		v.Editor = newEditor(ui, g, &numberEditor{9})
		fmt.Fprintf(v, "%d", ui.resp.Delay/time.Millisecond)
	}

	if v, err := g.SetView(HEADERS_VIEW, x0, split.Current(), x1, split.Next()); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Editable = true
		v.Editor = newEditor(ui, g, nil)
		v.Title = "Headers"
		var headers []string
		for key := range ui.resp.Headers {
			headers = append(headers, key+": "+ui.resp.Headers.Get(key))
		}
		fmt.Fprint(v, strings.Join(headers, "\n"))
	}

	if v, err := g.SetView(BODY_VIEW, x0, split.Current(), x1, y1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Editable = true
		v.Editor = newEditor(ui, g, nil)
		ui.renderBody(g)
	}

	return nil
}

func (ui *UI) Info(g *gocui.Gui, format string, args ...interface{}) {
	v, err := g.View(INFO_VIEW)
	if v == nil || err != nil {
		return
	}

	g.Execute(func(g *gocui.Gui) error {
		v.Clear()
		_, err := fmt.Fprintf(v, format, args...)
		return err
	})

	if ui.infoTimer != nil {
		ui.infoTimer.Stop()
	}
	ui.infoTimer = time.AfterFunc(3*time.Second, func() {
		g.Execute(func(g *gocui.Gui) error {
			v.Clear()
			return nil
		})
	})
}

func (ui *UI) Display(g *gocui.Gui, view string, bytes []byte) error {
	v, err := g.View(view)
	if err != nil {
		return err
	}

	g.Execute(func(g *gocui.Gui) error {
		v.Clear()
		_, err := v.Write(bytes)
		return err
	})

	return nil
}

func (ui *UI) Response() *httplab.Response {
	return ui.resp
}

func (ui *UI) nextView(g *gocui.Gui) error {
	if ui.hideResponseBuilder {
		return nil
	}
	ui.viewIndex = (ui.viewIndex + 1) % len(cicleable)
	return ui.setView(g, cicleable[ui.viewIndex])
}

func (ui *UI) prevView(g *gocui.Gui) error {
	if ui.hideResponseBuilder {
		return nil
	}
	ui.viewIndex = (ui.viewIndex - 1 + len(cicleable)) % len(cicleable)
	return ui.setView(g, cicleable[ui.viewIndex])
}

func (ui *UI) prevRequest(g *gocui.Gui) error {
	ui.reqLock.Lock()
	defer ui.reqLock.Unlock()

	if ui.currentRequest == 0 {
		return nil
	}

	ui.clearReveal()
	ui.currentRequest = ui.currentRequest - 1
	return ui.updateRequest(g)
}

func (ui *UI) nextRequest(g *gocui.Gui) error {
	ui.reqLock.Lock()
	defer ui.reqLock.Unlock()

	if ui.currentRequest >= len(ui.requests)-1 {
		return nil
	}

	ui.clearReveal()
	ui.currentRequest = ui.currentRequest + 1
	return ui.updateRequest(g)
}

func getViewBuffer(g *gocui.Gui, view string) string {
	v, err := g.View(view)
	if err != nil {
		return ""
	}
	return v.Buffer()
}

func (ui *UI) currentResponse(g *gocui.Gui) (*httplab.Response, error) {
	status := getViewBuffer(g, STATUS_VIEW)
	headers := getViewBuffer(g, HEADERS_VIEW)

	resp, err := httplab.NewResponse(status, headers, "")
	if err != nil {
		return nil, err
	}

	resp.Body = ui.resp.Body
	if ui.Response().Body.Mode == httplab.BodyInput {
		resp.Body.Input = []byte(getViewBuffer(g, BODY_VIEW))
	}

	delay := getViewBuffer(g, DELAY_VIEW)
	delay = strings.Trim(delay, " \n")
	intDelay, err := strconv.Atoi(delay)
	if err != nil {
		return nil, fmt.Errorf("Can't parse '%s' as number", delay)
	}
	resp.Delay = time.Duration(intDelay) * time.Millisecond

	return resp, nil
}

func (ui *UI) updateResponse(g *gocui.Gui) error {
	resp, err := ui.currentResponse(g)
	if err != nil {
		return err
	}

	ui.resp = resp
	return nil
}

func (ui *UI) restoreResponse(g *gocui.Gui, r *httplab.Response) {
	ui.resp = r

	var v *gocui.View
	v, _ = g.View(STATUS_VIEW)
	v.Clear()
	fmt.Fprintf(v, "%d", r.Status)

	v, _ = g.View(DELAY_VIEW)
	v.Clear()
	fmt.Fprintf(v, "%d", r.Delay)

	v, _ = g.View(HEADERS_VIEW)
	v.Clear()
	for key := range r.Headers {
		fmt.Fprintf(v, "%s: %s", key, r.Headers.Get(key))
	}

	ui.renderBody(g)

	ui.Info(g, "Response loaded!")
}

func (ui *UI) setView(g *gocui.Gui, view string) error {
	if err := ui.closePopup(g, ui.currentPopup); err != nil {
		return err
	}

	// Save cursor position before switch view
	cur := g.CurrentView()
	x, y := cur.Cursor()
	ui.cursors.Set(cur.Name(), x, y)

	_, err := g.SetCurrentView(view)
	return err
}

func (ui *UI) createPopupView(g *gocui.Gui, viewname string, w, h int) (*gocui.View, error) {
	maxX, maxY := g.Size()
	x := maxX/2 - w/2
	y := maxY/2 - h/2
	view, err := g.SetView(viewname, x, y, x+w, y+h)
	if err != nil && err != gocui.ErrUnknownView {
		return nil, err
	}

	return view, nil
}

func (ui *UI) closePopup(g *gocui.Gui, viewname string) error {
	if _, err := g.View(viewname); err != nil {
		if err == gocui.ErrUnknownView {
			return nil
		}
		return err
	}

	g.DeleteView(viewname)
	g.DeleteKeybindings(viewname)
	g.Cursor = true
	ui.currentPopup = ""
	return ui.setView(g, cicleable[ui.viewIndex])
}

func (ui *UI) openPopup(g *gocui.Gui, viewname string, x, y int) (*gocui.View, error) {
	view, err := ui.createPopupView(g, viewname, x, y)
	if err != nil {
		return nil, err
	}

	if err := ui.setView(g, view.Name()); err != nil {
		return nil, err
	}
	ui.currentPopup = viewname
	g.Cursor = false

	return view, nil
}

func (ui *UI) toggleHelp(g *gocui.Gui, help string) error {
	if ui.currentPopup == BINDINGS_VIEW {
		return ui.closePopup(g, BINDINGS_VIEW)
	}

	view, err := ui.openPopup(g, BINDINGS_VIEW, 40, strings.Count(help, "\n"))
	if err != nil {
		return err
	}

	view.Title = "Bindings"
	fmt.Fprint(view, help)

	return nil
}

func (ui *UI) toggleResponsesLoader(g *gocui.Gui) error {
	if ui.currentPopup == RESPONSES_VIEW {
		return ui.closePopup(g, RESPONSES_VIEW)
	}

	if err := ui.responses.Load(ui.configPath); err != nil {
		return err
	}

	if ui.responses.Len() == 0 {
		return errors.New("No responses has been saved")
	}

	popup, err := ui.openPopup(g, RESPONSES_VIEW, 30, ui.responses.Len()+1)
	if err != nil {
		return err
	}

	cx, _ := g.CurrentView().Cursor()
	onUp := func(g *gocui.Gui, v *gocui.View) error {
		ui.responses.Prev()
		v.SetCursor(cx, ui.responses.Index())
		return nil
	}

	onDown := func(g *gocui.Gui, v *gocui.View) error {
		ui.responses.Next()
		v.SetCursor(cx, ui.responses.Index())
		return nil
	}

	onDelete := func(g *gocui.Gui, v *gocui.View) error {
		key := ui.responses.Keys()[ui.responses.Index()]
		ui.responses.Del(key)
		if err := ui.responses.Save(ui.configPath); err != nil {
			return err
		}

		if err := ui.closePopup(g, RESPONSES_VIEW); err != nil {
			return err
		}

		if err := ui.toggleResponsesLoader(g); err != nil {
			return nil
		}

		return nil
	}

	onEnter := func(g *gocui.Gui, v *gocui.View) error {
		ui.restoreResponse(g, ui.responses.Cur())
		return nil
	}

	onQuit := func(g *gocui.Gui, v *gocui.View) error {
		return ui.closePopup(g, RESPONSES_VIEW)
	}

	view := []string{popup.Name()}
	(&bindings{
		{gocui.KeyArrowUp, "", "", view, func(*UI) ActionFn { return onUp }},
		{gocui.KeyArrowDown, "", "", view, func(*UI) ActionFn { return onDown }},
		{gocui.KeyEnter, "", "", view, func(*UI) ActionFn { return onEnter }},
		{'d', "", "", view, func(*UI) ActionFn { return onDelete }},
		{'q', "", "", view, func(*UI) ActionFn { return onQuit }},
	}).Apply(ui, g)

	for _, key := range ui.responses.Keys() {
		fmt.Fprintf(popup, "%s > %d\n", key, ui.responses.Get(key).Status)
	}

	popup.Title = "Responses"
	popup.Highlight = true
	return nil
}

func (ui *UI) toggleResponseBuilder(g *gocui.Gui) error {
	ui.hideResponseBuilder = !ui.hideResponseBuilder
	if ui.hideResponseBuilder {
		_, err := g.SetCurrentView(REQUEST_VIEW)
		return err
	}
	return nil
}

func (ui *UI) openSavePopup(g *gocui.Gui, title string, fn func(*gocui.Gui, string) error) error {
	if err := ui.closePopup(g, ui.currentPopup); err != nil {
		return err
	}

	popup, err := ui.openPopup(g, SAVE_VIEW, max(20, len(title)+3), 2)
	if err != nil {
		return err
	}

	onEnter := func(g *gocui.Gui, v *gocui.View) error {
		value := strings.Trim(v.Buffer(), " \n")
		if err := fn(g, value); err != nil {
			ui.Info(g, "%s", err.Error())
		}
		return ui.closePopup(g, SAVE_VIEW)
	}

	if err := g.SetKeybinding(popup.Name(), gocui.KeyEnter, gocui.ModNone, onEnter); err != nil {
		return err
	}

	popup.Title = title
	popup.Editable = true
	g.Cursor = true
	return nil
}

func (ui *UI) saveResponsePopup(g *gocui.Gui) error {
	fn := func(g *gocui.Gui, name string) error {
		return ui.saveResponseAs(g, name)
	}
	return ui.openSavePopup(g, "Save Response as...", fn)
}

func (ui *UI) saveResponseAs(g *gocui.Gui, name string) error {
	resp, err := ui.currentResponse(g)
	if err != nil {
		return err
	}

	ui.responses.Add(name, resp)
	if err := ui.responses.Save(ui.configPath); err != nil {
		return err
	}

	ui.Info(g, "Response applied and saved as '%s'", name)
	return nil
}

func (ui *UI) saveRequestPopup(g *gocui.Gui) error {
	// Only open the popup if there's requests
	if len(ui.requests) == 0 {
		ui.Info(g, "%s", "No Requests to save")
		return nil
	}

	fn := func(g *gocui.Gui, name string) error {
		return ui.saveRequestEncrypted(g, name)
	}

	return ui.openSavePopup(g, "Encrypt & Save Request as...", fn)
}

// saveRequestEncrypted persists the current request using envelope
// encryption (fresh DEK wrapped by the local KEK). The raw secret bytes
// never touch the file.
func (ui *UI) saveRequestEncrypted(g *gocui.Gui, name string) error {
	ui.reqLock.Lock()
	defer ui.reqLock.Unlock()
	if len(ui.requests) == 0 {
		return nil
	}
	captured := ui.requests[ui.currentRequest]

	blob, err := ui.guard.Keys.Seal(captured.PlainCopy(), 0, ui.guard.Now())
	if err != nil {
		return err
	}

	if err := os.WriteFile(name, blob, 0600); err != nil {
		return err
	}

	ui.guard.RecordEvent(security.Event{
		Action:     security.AuditSaveEncrypted,
		RequestID:  captured.ID,
		Method:     captured.Method,
		URI:        captured.URI,
		RemoteAddr: captured.RemoteAddr,
		Spans:      ui.guard.Snapshots(captured.Plain, captured.SensitiveSpans()),
		Detail:     "file: " + name,
	})

	ui.Info(g, "Request envelope-encrypted and saved as '%s' (0600)", name)
	return nil
}

func (ui *UI) exportRequestPopup(g *gocui.Gui) error {
	if len(ui.requests) == 0 {
		ui.Info(g, "%s", "No Requests to export")
		return nil
	}

	fn := func(g *gocui.Gui, name string) error {
		return ui.exportRequestTokenized(g, name)
	}

	return ui.openSavePopup(g, "Export tokenized Request as...", fn)
}

// exportRequestTokenized writes the current request with every sensitive
// value replaced by an irreversible, deterministic HMAC token. The original
// secrets can not be recovered from the export.
func (ui *UI) exportRequestTokenized(g *gocui.Gui, name string) error {
	ui.reqLock.Lock()
	defer ui.reqLock.Unlock()
	if len(ui.requests) == 0 {
		return nil
	}
	captured := ui.requests[ui.currentRequest]

	tokenized := ui.guard.Tokens.Apply(captured.PlainCopy(), captured.SensitiveSpans())
	if err := os.WriteFile(name, tokenized, 0600); err != nil {
		return err
	}

	ui.guard.RecordEvent(security.Event{
		Action:     security.AuditExport,
		RequestID:  captured.ID,
		Method:     captured.Method,
		URI:        captured.URI,
		RemoteAddr: captured.RemoteAddr,
		Spans:      ui.guard.Snapshots(captured.Plain, captured.SensitiveSpans()),
		Detail:     "file: " + name,
	})

	ui.Info(g, "Tokenized (irreversible) export saved as '%s' (0600)", name)
	return nil
}

func (ui *UI) renderBody(g *gocui.Gui) error {
	v, err := g.View(BODY_VIEW)
	if err != nil {
		return err
	}

	body := ui.resp.Body

	v.Title = fmt.Sprintf("Body (%s)", body.Mode)
	v.Clear()
	v.Write(body.Info())
	return nil
}

func (ui *UI) openBodyFilePopup(g *gocui.Gui) error {
	if err := ui.closePopup(g, ui.currentPopup); err != nil {
		return err
	}

	popup, err := ui.openPopup(g, FILE_DIALOG_VIEW, 20, 2)
	if err != nil {
		return err
	}

	g.Cursor = true
	popup.Title = "Open Body File"
	popup.Editable = true

	onEnter := func(g *gocui.Gui, v *gocui.View) error {
		path := strings.Trim(v.Buffer(), " \n")
		if path == "" {
			return ui.closePopup(g, popup.Name())
		}

		if err := ui.resp.Body.SetFile(path); err != nil {
			ui.Info(g, "%+v", err)
		} else {
			if err := ui.renderBody(g); err != nil {
				return err
			}
		}
		return ui.closePopup(g, popup.Name())
	}

	if err := g.SetKeybinding(popup.Name(), gocui.KeyEnter, gocui.ModNone, onEnter); err != nil {
		return err
	}

	return nil
}

func (ui *UI) nextBodyMode(g *gocui.Gui) error {
	modes := []httplab.BodyMode{
		httplab.BodyInput,
		httplab.BodyFile,
	}
	body := &ui.resp.Body
	body.Mode = body.Mode%httplab.BodyMode(len(modes)) + 1
	return ui.renderBody(g)
}

func (ui *UI) toggleLineWrap(g *gocui.Gui) error {
	view, err := g.View(REQUEST_VIEW)
	if err != nil {
		return err
	}

	view.Wrap = !view.Wrap
	return nil
}
