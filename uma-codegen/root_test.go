package main_test

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pckhoi/uma/testutil"
	main "github.com/pckhoi/uma/uma-codegen"
	"github.com/stretchr/testify/require"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(t, err)
	l, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startTestServer(t *testing.T, port int) (stop func()) {
	server := exec.Command("go", "run", "github.com/pckhoi/uma/uma-codegen/testdata", fmt.Sprintf("%d", port), "testdata/go-vcr")
	outr, err := server.StdoutPipe()
	require.NoError(t, err)
	errr, err := server.StderrPipe()
	require.NoError(t, err)
	started := make(chan bool, 1)
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(outr)
		for scanner.Scan() {
			s := scanner.Text()
			t.Logf("server stdout: %s", s)
			if s == "listening..." {
				started <- true
			}
		}
	}()
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(errr)
		for scanner.Scan() {
			s := scanner.Text()
			t.Logf("server stderr: %s", s)
		}
	}()
	require.NoError(t, server.Start())
	<-started
	return func() {
		t.Log("stopping server")
		testutil.AssertResponseStatus(t, http.MethodGet, fmt.Sprintf("http://localhost:%d/stop", port), "", http.StatusOK)
		require.NoError(t, server.Process.Signal(syscall.SIGTERM))
		server.Wait()
		wg.Wait()
	}
}

func TestRootCmd(t *testing.T) {
	cmd := main.RootCmd()
	cmd.SetArgs([]string{"testdata/openapi.yml", "main", "-o", "testdata/uma.gen.go"})
	require.NoError(t, cmd.Execute())

	client, stop := testutil.RecordHTTP(t, "test_uma_codegen", false)
	defer stop()
	kc := testutil.CreateKeycloakRPClient(t, client)

	port := getFreePort(t)
	stopServer := startTestServer(t, port)
	defer stopServer()

	time.Sleep(100 * time.Millisecond)
	baseURL := fmt.Sprintf("http://localhost:%d", port)
	testutil.AssertResponseStatus(t, http.MethodGet, baseURL+"/register-resources", "", http.StatusOK)

	accessTokens := map[string]string{}
	rpt := testutil.AskForRPT(t, kc, accessTokens, "johnd", http.MethodGet, baseURL+"/users", "")
	testutil.AssertResponseStatus(t, http.MethodGet, baseURL+"/users", rpt, http.StatusOK)

	rpt = testutil.AskForRPT(t, kc, accessTokens, "johnd", http.MethodPost, baseURL+"/users", rpt)
	testutil.AssertResponseStatus(t, http.MethodGet, baseURL+"/users", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, baseURL+"/users", rpt, http.StatusOK)

	rpt = testutil.AskForRPT(t, kc, accessTokens, "johnd", http.MethodGet, baseURL+"/users/1", rpt)
	testutil.AssertResponseStatus(t, http.MethodGet, baseURL+"/users", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, baseURL+"/users", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodGet, baseURL+"/users/1", rpt, http.StatusOK)

	rpt = testutil.AskForRPT(t, kc, accessTokens, "johnd", http.MethodPut, baseURL+"/users/1", rpt)
	testutil.AssertResponseStatus(t, http.MethodGet, baseURL+"/users", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPost, baseURL+"/users", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodGet, baseURL+"/users/1", rpt, http.StatusOK)
	testutil.AssertResponseStatus(t, http.MethodPut, baseURL+"/users/1", rpt, http.StatusOK)
}
