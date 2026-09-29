import { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";

import { Card, Spinner } from "@/components/ui";
import { useChat, useClearChat, useSendChat } from "@/hooks/useAi";

export default function ScanChat() {
  const { scanId } = useParams();
  const id = scanId ?? "";
  const { data, isLoading } = useChat(id || null);
  const send = useSendChat(id);
  const clear = useClearChat(id);
  const [question, setQuestion] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  const messages = data?.messages ?? [];

  // Keep the latest message in view as the conversation grows.
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages.length, send.isPending]);

  const submit = () => {
    const text = question.trim();
    if (!text || send.isPending) return;
    send.mutate(text);
    setQuestion("");
  };

  if (isLoading) return <Spinner />;

  return (
    <Card className="flex h-[70vh] flex-col p-0">
      <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-900">Ask AI about this scan</h2>
          <p className="text-xs text-slate-500">
            Grounded in this scan's findings. History is saved per scan.
          </p>
        </div>
        {messages.length > 0 ? (
          <button
            type="button"
            onClick={() => clear.mutate()}
            disabled={clear.isPending}
            className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 transition hover:bg-slate-50 disabled:opacity-50"
          >
            Clear
          </button>
        ) : null}
      </div>

      <div className="flex-1 space-y-3 overflow-y-auto px-5 py-4">
        {messages.length === 0 && !send.isPending ? (
          <div className="mx-auto mt-10 max-w-md text-center text-sm text-slate-500">
            <p className="font-medium text-slate-700">Ask anything about this scan.</p>
            <p className="mt-1">
              e.g. "What's my biggest risk?", "How do I fix the Kubernetes issues?", "Are any
              findings likely false positives?"
            </p>
          </div>
        ) : null}

        {messages.map((m) => (
          <div
            key={m.id}
            className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
          >
            <div
              className={`max-w-[80%] whitespace-pre-wrap rounded-2xl px-3.5 py-2 text-sm leading-relaxed ${
                m.role === "user"
                  ? "bg-brand text-white"
                  : "border border-violet-200 bg-violet-50/60 text-slate-800"
              }`}
            >
              {m.content}
            </div>
          </div>
        ))}

        {send.isPending ? (
          <div className="flex justify-start">
            <div className="rounded-2xl border border-violet-200 bg-violet-50/60 px-3.5 py-2 text-sm text-slate-500">
              Thinking…
            </div>
          </div>
        ) : null}

        {send.isError ? (
          <p className="rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700 ring-1 ring-inset ring-rose-600/20">
            {(send.error as Error).message}
          </p>
        ) : null}

        <div ref={endRef} />
      </div>

      <div className="flex gap-2 border-t border-slate-200 px-5 py-3">
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
          }}
          placeholder="Ask about this scan…"
          className="input flex-1"
        />
        <button
          type="button"
          onClick={submit}
          disabled={send.isPending || !question.trim()}
          className="rounded-lg bg-brand px-4 py-2 text-sm font-medium text-white transition hover:bg-brand/90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Send
        </button>
      </div>
    </Card>
  );
}
