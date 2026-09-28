import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  /** Remounts the boundary (clears the error) when this value changes. */
  resetKey?: string;
}

interface State {
  error: Error | null;
}

/**
 * Catches render-time exceptions in the page tree so a single failing view shows
 * a readable error instead of blanking the entire app. The surrounding app shell
 * (navigation, health status) stays interactive, and the error resets
 * automatically on navigation via `resetKey`.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Surface the details in the console for diagnosis.
    console.error("Unhandled UI error:", error, info.componentStack);
  }

  componentDidUpdate(prev: Props): void {
    if (prev.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null });
    }
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div className="mx-auto max-w-2xl">
        <div className="rounded-2xl border border-rose-200 bg-rose-50/60 p-6">
          <h1 className="text-lg font-semibold text-rose-800">This view hit an error</h1>
          <p className="mt-1 text-sm text-rose-700">
            Something went wrong while rendering this page. The rest of the app is still
            usable — you can navigate away and try again.
          </p>
          <pre className="mt-4 max-h-60 overflow-auto rounded-lg border border-rose-200 bg-white p-3 font-mono text-xs text-rose-900">
            {error.message}
            {error.stack ? `\n\n${error.stack}` : ""}
          </pre>
          <button
            type="button"
            onClick={() => this.setState({ error: null })}
            className="mt-4 inline-flex items-center rounded-lg bg-rose-600 px-3.5 py-2 text-sm font-medium text-white transition hover:bg-rose-700"
          >
            Try again
          </button>
        </div>
      </div>
    );
  }
}
