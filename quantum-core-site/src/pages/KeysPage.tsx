import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { KeyRound, RefreshCw, ShieldCheck } from "lucide-react";
import { getKeys, rotateKeys } from "../api/keys";
import { useToast } from "../hooks/useToast";
import { useAuth } from "../context/AuthContext";
import { PageHeader } from "../components/ui/PageHeader";
import { Card } from "../components/ui/Card";
import Button from "../components/ui/Button";
import ConfirmDialog from "../components/modals/ConfirmDialog";
import { useState } from "react";

export default function KeysPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const queryClient = useQueryClient();
  const toast = useToast();
  const { loading: authLoading } = useAuth();
  const [showRotate, setShowRotate] = useState(false);

  // Wait for auth to complete before firing the query so the access token
  // is guaranteed to be set in the axios interceptor.
  const { data: keys, isLoading, error } = useQuery({
    queryKey: ["keys", orgId],
    queryFn: () => getKeys(orgId!),
    enabled: !!orgId && !authLoading,
    retry: (failureCount, err: any) => {
      // Don't retry on 401 — it means the session truly expired
      if (err?.response?.status === 401) return false;
      return failureCount < 1;
    },
  });

  const rotateMut = useMutation({
    mutationFn: () => rotateKeys(orgId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["keys", orgId] });
      toast.success("Keys rotated successfully");
    },
    onError: (err: any) => toast.error(`Failed to rotate keys: ${err.message}`),
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-3 text-sm text-white/40">
        <div className="h-5 w-5 animate-spin rounded-full border-2 border-qb-cyan/30 border-t-qb-cyan" />
        Loading keys…
      </div>
    );
  }

  if (error) {
    const is401 = (error as any)?.response?.status === 401;
    return (
      <Card className="border-qb-rose/20 bg-qb-rose/5 p-6 text-center">
        <p className="mb-2 text-sm text-qb-rose">Failed to load keys</p>
        <p className="text-xs text-white/40">
          {is401
            ? "Your session may have expired — try refreshing the page."
            : "Make sure the backend server is running and accessible."}
        </p>
        <Button
          variant="ghost"
          size="sm"
          className="mt-4 text-xs"
          onClick={() => queryClient.invalidateQueries({ queryKey: ["keys", orgId] })}
        >
          Retry
        </Button>
      </Card>
    );
  }

  const keysArray = Array.isArray(keys) ? keys : [];
  const activeKey = keysArray.find((k) => k.isActive);
  const graceKeys = keysArray.filter((k) => !k.isActive);

  return (
    <div>
      <PageHeader
        title="Cryptographic keys"
        description="PQC keypairs for your organization. Rotated every 90 days."
        actions={
          activeKey && (
            <Button onClick={() => setShowRotate(true)} variant="secondary" size="sm" disabled={rotateMut.isPending}>
              <RefreshCw size={13} className="mr-1.5" />
              {rotateMut.isPending ? "Rotating…" : "Rotate now"}
            </Button>
          )
        }
      />

      {keysArray.length === 0 ? (
        <Card className="p-16 text-center">
          <KeyRound className="mx-auto mb-4 text-white/20" size={32} />
          <p className="mb-1 text-sm text-white/50">No cryptographic keys found</p>
          <p className="text-xs text-white/30">Keys are auto-generated when you create your first endpoint</p>
        </Card>
      ) : (
        <>
          {activeKey && (
            <Card variant="accent" className="mb-4 overflow-hidden p-6">
              <div className="mb-6 flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-qb-emerald/30 bg-qb-emerald/10 text-qb-emerald">
                    <KeyRound size={18} />
                  </div>
                  <div>
                    <div className="mb-1 flex items-center gap-2.5">
                      <span className="text-lg font-bold">Version {activeKey.version}</span>
                      <span className="rounded-full border border-qb-emerald/20 bg-qb-emerald/10 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-qb-emerald">
                        Active
                      </span>
                    </div>
                    <div className="text-xs text-white/40">
                      Generated {new Date(activeKey.createdAt).toLocaleDateString()} — expires {new Date(activeKey.expiresAt).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                <div>
                  <div className="mb-2 text-xs text-white/40">ECDSA P-256 public key</div>
                  <div className="max-h-28 overflow-auto rounded-lg border border-white/5 bg-black/40 p-4 font-mono-qb text-xs whitespace-pre-wrap break-all text-white/60">
                    {activeKey.ecdsaPublicKey}
                  </div>
                </div>
                <div>
                  <div className="mb-2 text-xs text-white/40">ML-DSA-65 public key</div>
                  <div className="max-h-28 overflow-auto rounded-lg border border-white/5 bg-black/40 p-4 font-mono-qb text-xs whitespace-pre-wrap break-all text-white/60">
                    {activeKey.dilithiumPublicKey}
                  </div>
                </div>
              </div>
            </Card>
          )}

          {graceKeys.map((gk) => (
            <Card key={gk.version} className="mb-4 p-5 opacity-65">
              <div className="flex items-center gap-3">
                <span className="text-lg font-bold text-white/60">Version {gk.version}</span>
                <span className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-white/40">
                  Grace period
                </span>
              </div>
              <div className="mt-1 text-xs text-white/30">
                Retired {new Date(gk.expiresAt).toLocaleDateString()} — grace expires{" "}
                {gk.graceExpiresAt ? new Date(gk.graceExpiresAt).toLocaleDateString() : "unknown"}
              </div>
            </Card>
          ))}

          <Card className="mt-8 p-5">
            <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck size={15} className="text-qb-cyan" />
              Auto-rotation schedule
            </div>
            <p className="text-sm leading-relaxed text-white/45">
              {activeKey
                ? `Next automatic rotation: ${new Date(activeKey.expiresAt).toLocaleDateString()}. `
                : "Automatic rotation is scheduled. "}
              The previous keypair is retained for 24 hours after rotation to verify in-flight requests. Private keys are never exposed — all signing happens server-side.
            </p>
          </Card>
        </>
      )}

      <ConfirmDialog
        isOpen={showRotate}
        title="Rotate keys now?"
        message="The old keys will remain in a grace period for 24h to verify in-flight requests."
        confirmText="Rotate"
        onConfirm={() => {
          setShowRotate(false);
          rotateMut.mutate();
        }}
        onClose={() => setShowRotate(false)}
      />
    </div>
  );
}
