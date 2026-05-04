type Props = {
  children: string;
  tone?: "neutral" | "good" | "warn" | "bad";
};

export function StatusPill({ children, tone = "neutral" }: Props) {
  return <span className={`status-pill ${tone}`}>{children}</span>;
}
