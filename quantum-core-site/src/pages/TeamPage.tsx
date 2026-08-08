import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { listMembers, inviteMember, removeMember, type OrgMember } from "../api/team";
import { useAuth } from "../context/AuthContext";
import { PageHeader } from "../components/ui/PageHeader";
import { Card } from "../components/ui/Card";
import { Modal } from "../components/ui/Modal";
import Button from "../components/ui/Button";
import { cn } from "../lib/utils";

const roleChip: Record<string, string> = {
  owner: "bg-qb-violet/10 text-qb-violet border-qb-violet/20",
  admin: "bg-qb-cyan/10 text-qb-cyan border-qb-cyan/20",
  viewer: "bg-white/5 text-white/55 border-white/10",
};
const statusChip: Record<string, string> = {
  active: "bg-qb-emerald/10 text-qb-emerald border-qb-emerald/20",
  pending: "bg-qb-amber/10 text-qb-amber border-qb-amber/20",
};

export default function TeamPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const queryClient = useQueryClient();
  const { loading: authLoading } = useAuth();
  const [showModal, setShowModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "viewer">("viewer");
  const [errorMsg, setErrorMsg] = useState("");

  const { data: members, isLoading } = useQuery({
    queryKey: ["members", orgId],
    queryFn: () => listMembers(orgId!),
    enabled: !!orgId && !authLoading,
  });

  const inviteMut = useMutation({
    mutationFn: () => inviteMember(orgId!, { email: inviteEmail, role: inviteRole }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["members", orgId] });
      setShowModal(false);
      setInviteEmail("");
      setErrorMsg("");
    },
    onError: (err: any) => setErrorMsg(err.message || "Failed to invite member"),
  });

  const removeMut = useMutation({
    mutationFn: (userId: string) => removeMember(orgId!, userId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["members", orgId] }),
  });

  return (
    <div>
      <PageHeader
        title="Team"
        description="Manage members and roles"
        actions={
          <Button onClick={() => setShowModal(true)} variant="primary" size="sm">
            <UserPlus size={15} className="mr-1.5" />
            Invite member
          </Button>
        }
      />

      <Card className="p-6">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-white/[0.06] text-white/40">
                <th className="pb-3 font-medium">Member</th>
                <th className="pb-3 font-medium">Role</th>
                <th className="pb-3 font-medium">Status</th>
                <th className="pb-3 font-medium">Joined</th>
                <th className="pb-3" />
              </tr>
            </thead>
            <tbody className="text-white/80">
              {isLoading ? (
                <tr><td colSpan={5} className="py-4 text-center text-white/40">Loading members…</td></tr>
              ) : !members || members.length === 0 ? (
                <tr><td colSpan={5} className="py-4 text-center text-white/40">No members found</td></tr>
              ) : (
                members.map((m: OrgMember) => {
                  const name = m.userId?.name || m.inviteEmail || "Pending User";
                  const email = m.userId?.email || m.inviteEmail;
                  return (
                    <tr key={m._id} className="border-b border-white/[0.06] transition-colors hover:bg-white/[0.02]">
                      <td className="py-4">
                        <div className="flex items-center gap-3">
                          <div className="flex h-9 w-9 items-center justify-center rounded-full border border-qb-cyan/20 bg-gradient-to-br from-qb-cyan/20 to-qb-violet/20 text-xs font-bold uppercase text-white">
                            {name.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <div className="font-medium text-white">{name}</div>
                            {email && <div className="text-xs text-white/40">{email}</div>}
                          </div>
                        </div>
                      </td>
                      <td className="py-4">
                        <span className={cn("rounded-full border px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-wider", roleChip[m.role] ?? roleChip.viewer)}>
                          {m.role}
                        </span>
                      </td>
                      <td className="py-4">
                        <span className={cn("rounded-full border px-2.5 py-0.5 text-[10px] font-medium capitalize", statusChip[m.status] ?? statusChip.pending)}>
                          {m.status}
                        </span>
                      </td>
                      <td className="py-4 text-xs text-white/40">{new Date(m.createdAt).toLocaleDateString()}</td>
                      <td className="py-4 text-right">
                        {m.role !== "owner" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              if (confirm(`Remove ${email} from the organization?`)) {
                                removeMut.mutate(m.userId?._id || m._id);
                              }
                            }}
                            disabled={removeMut.isPending}
                            className="hover:border-qb-rose/30 hover:text-qb-rose"
                          >
                            Remove
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal
        open={showModal}
        onOpenChange={(o) => {
          setShowModal(o);
          if (!o) {
            setInviteEmail("");
            setErrorMsg("");
          }
        }}
        title="Invite member"
        description="Send an invitation to join this organization."
        footer={
          <>
            <Button type="button" variant="ghost" size="sm" onClick={() => setShowModal(false)}>Cancel</Button>
            <Button type="submit" form="invite-form" variant="primary" size="sm" disabled={inviteMut.isPending}>
              {inviteMut.isPending ? "Inviting…" : "Send Invite"}
            </Button>
          </>
        }
      >
        {errorMsg && (
          <div className="mb-4 rounded-lg border border-qb-rose/20 bg-qb-rose/5 p-3 text-sm text-qb-rose">{errorMsg}</div>
        )}
        <form id="invite-form" onSubmit={(e) => { e.preventDefault(); inviteMut.mutate(); }} className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-xs text-white/60">Email Address</label>
            <input
              type="email"
              required
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              className="qb-input-focus w-full rounded-xl border border-white/10 bg-black/40 p-2.5 text-sm text-white placeholder-white/20"
              placeholder="colleague@domain.com"
            />
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs text-white/60">Role</label>
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as "admin" | "viewer")}
              className="qb-input-focus w-full rounded-xl border border-white/10 bg-black/40 p-2.5 text-sm text-white"
            >
              <option value="viewer">Viewer (Read-only)</option>
              <option value="admin">Admin (Can manage endpoints & keys)</option>
            </select>
          </div>
        </form>
      </Modal>
    </div>
  );
}
