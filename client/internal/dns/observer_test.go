package dns_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/dns/test"
)

type replyHandler struct {
	answer dns.RR
}

func (h replyHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	if h.answer != nil {
		resp.Answer = []dns.RR{h.answer}
	}
	_ = w.WriteMsg(resp)
}

type recordingObserver struct {
	mu     sync.Mutex
	calls  int
	err    error
	seen   bool
	onSeen func()
}

func (o *recordingObserver) ObserveResponse(_ *dns.Msg, resp *dns.Msg) error {
	o.mu.Lock()
	o.calls++
	o.seen = resp != nil
	onSeen := o.onSeen
	err := o.err
	o.mu.Unlock()
	if onSeen != nil {
		onSeen()
	}
	return err
}

func (o *recordingObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls
}

func TestResponseObserverSeesUpstreamAnswerBeforeWrite(t *testing.T) {
	chain := nbdns.NewHandlerChain()
	answer, err := dns.NewRR("example.com. 60 IN A 192.0.2.10")
	require.NoError(t, err)
	chain.AddHandler("example.com.", replyHandler{answer: answer}, nbdns.PriorityUpstream)

	observer := &recordingObserver{}
	writer := &test.MockResponseWriter{}
	observer.onSeen = func() {
		assert.Nil(t, writer.GetLastResponse(),
			"the observer must run before the response is released")
	}
	chain.SetResponseObserver(observer)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	chain.ServeDNS(writer, req)

	assert.Equal(t, 1, observer.count())
	require.NotNil(t, writer.GetLastResponse())
	require.Len(t, writer.GetLastResponse().Answer, 1)
}

func TestResponseObserverSkipsLocalZones(t *testing.T) {
	chain := nbdns.NewHandlerChain()
	chain.AddHandler("example.com.", replyHandler{}, nbdns.PriorityLocal)

	observer := &recordingObserver{}
	chain.SetResponseObserver(observer)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	writer := &test.MockResponseWriter{}
	chain.ServeDNS(writer, req)

	assert.Zero(t, observer.count(), "a local zone answer must keep precedence")
	assert.NotNil(t, writer.GetLastResponse())
}

func TestResponseObserverFailureWithholdsAnswer(t *testing.T) {
	chain := nbdns.NewHandlerChain()
	answer, err := dns.NewRR("example.com. 60 IN A 192.0.2.11")
	require.NoError(t, err)
	chain.AddHandler("example.com.", replyHandler{answer: answer}, nbdns.PriorityUpstream)

	observer := &recordingObserver{err: errors.New("kernel set update failed")}
	chain.SetResponseObserver(observer)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	writer := &test.MockResponseWriter{}
	chain.ServeDNS(writer, req)

	assert.Equal(t, 1, observer.count())
	assert.Nil(t, writer.GetLastResponse(),
		"a failed observation must not release a usable answer")
}
