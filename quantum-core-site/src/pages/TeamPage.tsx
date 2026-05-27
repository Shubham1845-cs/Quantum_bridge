import { useState } from "react";
import { motion } from "framer-motion";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listMembers, inviteMember, removeMember, type OrgMember } from "../api/team";

export default function TeamPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const queryClient = useQueryClient();
  const [showModal, setShowModal] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"admin" | "viewer">("viewer");
  const [errorMsg, setErrorMsg] = useState("");

  const { data: members, isLoading } = useQuery({
    queryKey: ["members", orgId],
    queryFn: () => listMembers(orgId!),
    enabled: !!orgId,
  });

  const inviteMut = useMutation({
    mutationFn: () => inviteMember(orgId!, { email: inviteEmail, role: inviteRole }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["members", orgId] });
      setShowModal(false);
      setInviteEmail("");
      setErrorMsg("");
    },
    onError: (err: any) => {
      setErrorMsg(err.message || "Failed to invite member");
    }
  });

  const removeMut = useMutation({
    mutationFn: (userId: string) => removeMember(orgId!, userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["members", orgId] });
    }
  });

  const handleInvite = (e: React.FormEvent) => {
    e.preventDefault();
    inviteMut.mutate();
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="flex justify-between items-start mb-8">
        <div>
          <h2 className="text-2xl font-bold tracking-tight mb-1">Team</h2>
          <p className="text-white/40 text-sm">Manage members and roles</p>
        </div>
        <button 
          onClick={() => setShowModal(true)}
          className="px-4 py-2 bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/30 rounded-lg text-sm font-medium hover:bg-cyber-cyan/20 transition-colors"
        >
          + Invite member
        </button>
      </div>

      <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead>
              <tr className="text-white/40 border-b border-white/[0.06]">
                <th className="pb-3 font-medium">Member</th>
                <th className="pb-3 font-medium">Role</th>
                <th className="pb-3 font-medium">Status</th>
                <th className="pb-3 font-medium">Joined</th>
                <th className="pb-3 font-medium"></th>
              </tr>
            </thead>
            <tbody className="text-white/80">
              {isLoading ? (
                <tr><td colSpan={5} className="py-4 text-center text-white/40">Loading members...</td></tr>
              ) : !members || members.length === 0 ? (
                <tr><td colSpan={5} className="py-4 text-center text-white/40">No members found</td></tr>
              ) : (
                members.map((m: OrgMember) => (
                  <tr key={m._id} className="border-b border-white/[0.06]">
                    <td className="py-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-blue-500/20 text-blue-400 flex items-center justify-center text-xs font-bold border border-blue-500/30">
                          {(m.userId?.name || m.inviteEmail || m.userId?.email || "?").charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div className="font-medium">{m.userId?.name || m.inviteEmail || "Pending User"}</div>
                          <div className="text-xs text-white/40">{m.userId?.email || m.inviteEmail}</div>
                        </div>
                      </div>
                    </td>
                    <td className="py-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${
                        m.role === 'owner' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' : 
                        m.role === 'admin' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' : 
                        'bg-white/5 text-white/60 border-white/10'
                      }`}>
                        {m.role.charAt(0).toUpperCase() + m.role.slice(1)}
                      </span>
                    </td>
                    <td className="py-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${
                        m.status === 'active' ? 'bg-green-500/10 text-green-400 border-green-500/20' : 
                        'bg-orange-500/10 text-orange-400 border-orange-500/20'
                      }`}>
                        {m.status.charAt(0).toUpperCase() + m.status.slice(1)}
                      </span>
                    </td>
                    <td className="py-4 text-white/40 text-xs">{new Date(m.createdAt).toLocaleDateString()}</td>
                    <td className="py-4">
                      {m.role !== 'owner' && (
                        <button 
                          onClick={() => {
                            if (confirm(`Remove ${m.userId?.email || m.inviteEmail} from the organization?`)) {
                              removeMut.mutate(m.userId?._id || m._id);
                            }
                          }}
                          disabled={removeMut.isPending}
                          className="px-2 py-1 border border-white/10 rounded text-[10px] text-white/60 hover:text-white hover:bg-white/5 transition-colors disabled:opacity-50"
                        >
                          {removeMut.isPending ? "..." : "Remove"}
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#111111] border border-white/10 rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <h3 className="text-xl font-bold mb-4">Invite member</h3>
            {errorMsg && <div className="mb-4 text-red-400 text-sm bg-red-400/10 p-2 rounded">{errorMsg}</div>}
            <form onSubmit={handleInvite}>
              <div className="mb-4">
                <label className="block text-white/60 text-xs mb-1">Email Address</label>
                <input 
                  type="email" 
                  required
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className="w-full bg-white/5 border border-white/10 rounded p-2 text-sm text-white placeholder-white/20 focus:border-cyber-cyan focus:outline-none" 
                  placeholder="colleague@domain.com"
                />
              </div>
              <div className="mb-6">
                <label className="block text-white/60 text-xs mb-1">Role</label>
                <select 
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as "admin" | "viewer")}
                  className="w-full bg-white/5 border border-white/10 rounded p-2 text-sm text-white outline-none focus:border-cyber-cyan"
                >
                  <option value="viewer">Viewer (Read-only)</option>
                  <option value="admin">Admin (Can manage endpoints & keys)</option>
                </select>
              </div>
              <div className="flex justify-end gap-3">
                <button 
                  type="button" 
                  onClick={() => setShowModal(false)}
                  className="px-4 py-2 text-sm text-white/60 hover:text-white"
                >
                  Cancel
                </button>
                <button 
                  type="submit" 
                  disabled={inviteMut.isPending}
                  className="px-4 py-2 bg-cyber-cyan text-black rounded text-sm font-medium hover:bg-cyber-cyan/80 disabled:opacity-50"
                >
                  {inviteMut.isPending ? "Inviting..." : "Send Invite"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </motion.div>
  );
}

