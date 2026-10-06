import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("HoneyMesh UI crashed:", error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="alert" role="alert">
          <strong>This view crashed.</strong>
          <div className="json" style={{ marginTop: 10 }}>
            {this.state.error.message}
          </div>
          <button
            type="button"
            className="btn"
            style={{ marginTop: 10 }}
            onClick={() => this.setState({ error: null })}
          >
            try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
