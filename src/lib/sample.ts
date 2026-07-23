// A small, realistic sample HAR so the demo visibly redacts something: it carries
// an Authorization: Bearer header, a Set-Cookie, an access_token query param, and a
// JWT inside a JSON request body. Loading it should light up every category.

export const SAMPLE_HAR = JSON.stringify(
  {
    log: {
      version: "1.2",
      creator: { name: "harkit-sample", version: "0.1.0" },
      entries: [
        {
          startedDateTime: "2026-07-23T09:14:02.101Z",
          time: 143,
          request: {
            method: "POST",
            url: "https://api.example.com/v1/login?access_token=ya29.AbCdEf-secret-value&redirect=%2Fhome",
            httpVersion: "HTTP/2",
            headers: [
              { name: "content-type", value: "application/json" },
              { name: "authorization", value: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.s5H1Qk8oR2wZ0abcXYZ-deadbeef" },
              { name: "x-api-key", value: "demo_apikey_9f8a7b6c5d4e3f2a1b0c9d8e" },
              { name: "user-agent", value: "Mozilla/5.0" },
            ],
            cookies: [
              { name: "session", value: "s%3AaB9k2mQ1.longsignedsessionvaluehere" },
            ],
            queryString: [
              { name: "access_token", value: "ya29.AbCdEf-secret-value" },
              { name: "redirect", value: "/home" },
            ],
            postData: {
              mimeType: "application/json",
              text: "{\"email\":\"dev@example.com\",\"password\":\"hunter2-not-safe\",\"id_token\":\"eyJhbGciOiJSUzI1NiJ9.eyJlbWFpbCI6ImRldkBleGFtcGxlLmNvbSJ9.QWxhZGRpbjpvcGVuc2VzYW1l\",\"remember\":true}",
            },
            headersSize: -1,
            bodySize: 214,
          },
          response: {
            status: 200,
            statusText: "OK",
            httpVersion: "HTTP/2",
            headers: [
              { name: "content-type", value: "application/json" },
              { name: "set-cookie", value: "sid=8fH2kLmn9Pqr; HttpOnly; Secure; SameSite=Strict" },
              { name: "x-auth-token", value: "4c2a1f9e8d7b6a5c" },
            ],
            cookies: [
              { name: "sid", value: "8fH2kLmn9Pqr" },
            ],
            content: {
              size: 118,
              mimeType: "application/json",
              text: "{\"ok\":true,\"user\":{\"id\":123456,\"email\":\"dev@example.com\"},\"refresh_token\":\"rt_7a6b5c4d3e2f1g0h\"}",
            },
            redirectURL: "",
            headersSize: -1,
            bodySize: 118,
          },
          cache: {},
          timings: { send: 1, wait: 140, receive: 2 },
          serverIPAddress: "203.0.113.42",
        },
        {
          startedDateTime: "2026-07-23T09:14:03.402Z",
          time: 88,
          request: {
            method: "GET",
            url: "https://api.example.com/v1/profile?fields=name,plan",
            httpVersion: "HTTP/2",
            headers: [
              { name: "accept", value: "application/json" },
              { name: "cookie", value: "sid=8fH2kLmn9Pqr; theme=dark" },
            ],
            cookies: [
              { name: "sid", value: "8fH2kLmn9Pqr" },
              { name: "theme", value: "dark" },
            ],
            queryString: [{ name: "fields", value: "name,plan" }],
            headersSize: -1,
            bodySize: 0,
          },
          response: {
            status: 200,
            statusText: "OK",
            httpVersion: "HTTP/2",
            headers: [{ name: "content-type", value: "application/json" }],
            cookies: [],
            content: {
              size: 64,
              mimeType: "application/json",
              text: "{\"name\":\"Dev Example\",\"plan\":\"pro\",\"ip\":\"198.51.100.7\"}",
            },
            redirectURL: "",
            headersSize: -1,
            bodySize: 64,
          },
          cache: {},
          timings: { send: 1, wait: 85, receive: 2 },
          serverIPAddress: "203.0.113.42",
        },
      ],
    },
  },
  null,
  2,
);
