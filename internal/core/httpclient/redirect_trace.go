package httpclient

import (
	"context"
	"encoding/json"
	"fmt"

	"sentinelhttp/internal/core/network"
	"sentinelhttp/internal/core/redirectanalysis"
)

const defaultMaxRedirects = 10
const hardMaxRedirects = 20

type RedirectOptions struct {
	MaxRedirects int
	SameHost     bool
}

type RedirectStop string

const (
	RedirectTerminal          RedirectStop = "terminal_response"
	RedirectLocationMissing   RedirectStop = "location_missing"
	RedirectLocationAmbiguous RedirectStop = "location_ambiguous"
	RedirectLocationInvalid   RedirectStop = "location_invalid"
	RedirectTargetInvalid     RedirectStop = "target_invalid"
	RedirectDowngradeBlocked  RedirectStop = "downgrade_blocked"
	RedirectSameHostBlocked   RedirectStop = "same_host_blocked"
	RedirectLoop              RedirectStop = "loop_detected"
	RedirectLimit             RedirectStop = "redirect_limit"
	RedirectRequestFailed     RedirectStop = "request_failed"
)

type RedirectObservationCode string

const (
	RedirectCrossHost     RedirectObservationCode = "cross_host"
	RedirectSchemeChanged RedirectObservationCode = "scheme_changed"
	RedirectDowngrade     RedirectObservationCode = "downgrade_blocked"
)

type RedirectObservation struct {
	Code RedirectObservationCode
	Hop  int
}

type RedirectHop struct {
	Target         network.Target
	Response       *Response
	LocationStatus redirectanalysis.LocationStatus
	NextTarget     network.Target
}

func (h RedirectHop) String() string {
	status := 0
	if h.Response != nil {
		status = h.Response.Metadata().StatusCode
	}
	return fmt.Sprintf("redirect hop %s: status=%d location=%s", h.Target.SafeURL(), status, h.LocationStatus)
}

func (h RedirectHop) GoString() string { return h.String() }

func (h RedirectHop) MarshalJSON() ([]byte, error) {
	next := ""
	if h.LocationStatus == redirectanalysis.LocationValid && h.NextTarget.RequestURL() != "" {
		next = h.NextTarget.SafeURL()
	}
	return json.Marshal(struct {
		Target         network.Target                  `json:"target"`
		Response       *Response                       `json:"response"`
		LocationStatus redirectanalysis.LocationStatus `json:"location_status"`
		NextTarget     string                          `json:"next_target,omitempty"`
	}{h.Target, h.Response, h.LocationStatus, next})
}

type RedirectTrace struct {
	Hops              []RedirectHop
	Stop              RedirectStop
	Responses         int
	RedirectsFollowed int
	Observations      []RedirectObservation
}

func (t RedirectTrace) String() string {
	return fmt.Sprintf("redirect trace: hops=%d responses=%d followed=%d stop=%s", len(t.Hops), t.Responses, t.RedirectsFollowed, t.Stop)
}

func (t RedirectTrace) GoString() string { return t.String() }

func (t RedirectTrace) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Hops              []RedirectHop         `json:"hops"`
		Stop              RedirectStop          `json:"stop"`
		Responses         int                   `json:"responses"`
		RedirectsFollowed int                   `json:"redirects_followed"`
		Observations      []RedirectObservation `json:"observations"`
	}{t.Hops, t.Stop, t.Responses, t.RedirectsFollowed, t.Observations})
}

// TraceRedirects explicitly follows a bounded GET journey. Every attempted hop
// passes through the existing one-exchange boundary and records owned evidence.
func (c *Client) TraceRedirects(ctx context.Context, initial network.Target, opts RedirectOptions) (*RedirectTrace, error) {
	trace := &RedirectTrace{}
	if c == nil || c.boundary == nil || ctx == nil || c.config.TotalTimeout <= 0 || opts.MaxRedirects < 0 || opts.MaxRedirects > hardMaxRedirects {
		return trace, fault(ConfigInvalid)
	}
	limit := opts.MaxRedirects
	if limit == 0 {
		limit = defaultMaxRedirects
	}
	batch, cancel := context.WithTimeout(ctx, c.config.TotalTimeout)
	defer cancel()
	current := initial
	seen := map[string]bool{current.RequestURL(): true}
	for {
		response, err := c.do(batch, current, GET, exchangeProfile{headersOnly: true})
		trace.Hops = append(trace.Hops, RedirectHop{Target: current, Response: response, LocationStatus: redirectanalysis.LocationNotApplicable})
		if err != nil {
			trace.Stop = RedirectRequestFailed
			return trace, err
		}
		trace.Responses++
		if len(trace.Hops) > 1 {
			trace.RedirectsFollowed++
		}
		status := response.Metadata().StatusCode
		if !redirectanalysis.IsFollowStatus(status) {
			trace.Stop = RedirectTerminal
			return trace, nil
		}
		candidate, locationStatus := redirectanalysis.ResolveLocation(current.RequestURL(), response.HeaderValues("Location"))
		hop := &trace.Hops[len(trace.Hops)-1]
		hop.LocationStatus = locationStatus
		switch locationStatus {
		case redirectanalysis.LocationMissing:
			trace.Stop = RedirectLocationMissing
			return trace, nil
		case redirectanalysis.LocationAmbiguous:
			trace.Stop = RedirectLocationAmbiguous
			return trace, nil
		case redirectanalysis.LocationInvalid:
			trace.Stop = RedirectLocationInvalid
			return trace, nil
		}
		next, parseErr := network.ParseTarget(candidate)
		if parseErr != nil {
			trace.Stop = RedirectTargetInvalid
			return trace, nil
		}
		hop.NextTarget = next
		if next.Host() != current.Host() {
			trace.Observations = append(trace.Observations, RedirectObservation{RedirectCrossHost, len(trace.Hops) - 1})
		}
		if next.Scheme() != current.Scheme() {
			trace.Observations = append(trace.Observations, RedirectObservation{RedirectSchemeChanged, len(trace.Hops) - 1})
		}
		if current.Scheme() == "https" && next.Scheme() == "http" {
			trace.Observations = append(trace.Observations, RedirectObservation{RedirectDowngrade, len(trace.Hops) - 1})
			trace.Stop = RedirectDowngradeBlocked
			return trace, nil
		}
		if opts.SameHost && next.Host() != initial.Host() {
			trace.Stop = RedirectSameHostBlocked
			return trace, nil
		}
		if seen[next.RequestURL()] {
			trace.Stop = RedirectLoop
			return trace, nil
		}
		if trace.RedirectsFollowed >= limit {
			trace.Stop = RedirectLimit
			return trace, nil
		}
		seen[next.RequestURL()] = true
		current = next
	}
}
