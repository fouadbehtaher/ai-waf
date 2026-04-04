export default function LoginScreen({ form, onChange, onSubmit, busy, authLoading, error }) {
  return (
    <div className="login-shell">
      <div className="ambient ambient-a" />
      <div className="ambient ambient-b" />
      <section className="login-card">
        <div>
          <span className="hero-kicker">AI-Based Web Application Firewall</span>
          <h1>Sign in to the project dashboard.</h1>
          <p>
            This dashboard gives authorized users access to live request inspection, attack monitoring, labeling,
            blocking decisions, policy control, and operational reporting for the AI-based WAF.
          </p>
        </div>

        <form className="login-form" onSubmit={onSubmit}>
          <label className="field">
            <span>Username</span>
            <input
              type="text"
              value={form.username}
              onChange={(event) => onChange("username", event.target.value)}
              placeholder="admin"
              autoComplete="username"
            />
          </label>

          <label className="field">
            <span>Password</span>
            <input
              type="password"
              value={form.password}
              onChange={(event) => onChange("password", event.target.value)}
              placeholder="Admin123!"
              autoComplete="current-password"
            />
          </label>

          <button className="primary-button" type="submit" disabled={busy || authLoading}>
            {authLoading ? "Checking session..." : busy ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <div className="credential-hint">
          <strong>Demo accounts</strong>
          <span>`admin / Admin123!`</span>
          <span>`analyst / Analyst123!`</span>
          <span>`viewer / Viewer123!`</span>
        </div>

        {error ? <div className="login-error">{error}</div> : null}
      </section>
    </div>
  );
}
