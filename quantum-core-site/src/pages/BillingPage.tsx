import { motion } from "framer-motion";
import { useParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { createCheckoutSession, getCustomerPortalUrl } from "../api/billing";

export default function BillingPage() {
  const { orgId } = useParams<{ orgId: string }>();

  const checkoutMut = useMutation({
    mutationFn: () => createCheckoutSession(orgId!, "enterprise"),
    onSuccess: (data) => {
      window.location.href = data.url;
    },
    onError: (err: any) => {
      alert(`Failed to create checkout session: ${err.message}`);
    }
  });

  const portalMut = useMutation({
    mutationFn: () => getCustomerPortalUrl(orgId!),
    onSuccess: (data) => {
      window.location.href = data.url;
    },
    onError: (err: any) => {
      alert(`Failed to access billing portal: ${err.message}`);
    }
  });

  return (
    <motion.div
      initial={{ opacity: 0, y: 15 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
    >
      <div className="mb-8">
        <h2 className="text-2xl font-bold tracking-tight mb-1">Billing & Usage</h2>
        <p className="text-white/40 text-sm">Manage your Enterprise plan and review usage limits</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-start mb-4">
              <div>
                <div className="font-bold text-lg mb-1">Enterprise Plan</div>
                <div className="text-white/40 text-xs">Custom limits, dedicated HSM</div>
              </div>
              <span className="text-xl font-bold">$1,200<span className="text-sm font-normal text-white/40">/mo</span></span>
            </div>
            
            <div className="space-y-2 mb-6">
              <div className="flex items-center gap-2 text-sm text-white/70">
                <span className="text-green-400">✓</span> Unlimited endpoints
              </div>
              <div className="flex items-center gap-2 text-sm text-white/70">
                <span className="text-green-400">✓</span> 99.99% uptime SLA
              </div>
              <div className="flex items-center gap-2 text-sm text-white/70">
                <span className="text-green-400">✓</span> Dedicated FIPS 140-3 HSM
              </div>
            </div>
          </div>
          
          <button 
            onClick={() => checkoutMut.mutate()}
            disabled={checkoutMut.isPending}
            className="w-full py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/10 transition-colors disabled:opacity-50"
          >
            {checkoutMut.isPending ? "Redirecting..." : "Upgrade to Enterprise"}
          </button>
        </div>

        <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
          <h3 className="font-bold text-base mb-4">Usage this month</h3>
          
          <div className="mb-6">
            <div className="flex justify-between mb-1 text-sm">
              <span className="text-white/60">Requests</span>
              <span><span className="font-bold">841,200</span> <span className="text-white/40">/ 1,000,000</span></span>
            </div>
            <div className="h-2 w-full bg-white/[0.06] rounded-full overflow-hidden mb-1">
              <div className="h-full bg-blue-500" style={{ width: '84%' }} />
            </div>
            <div className="text-[10px] text-white/40 text-right">Resets in 11 days</div>
          </div>
          
          <div className="mb-4">
            <div className="flex justify-between mb-1 text-sm">
              <span className="text-white/60">Endpoints</span>
              <span><span className="font-bold">2</span> <span className="text-white/40">/ Unlimited</span></span>
            </div>
            <div className="h-2 w-full bg-white/[0.06] rounded-full overflow-hidden">
              <div className="h-full bg-cyber-cyan w-1/12" />
            </div>
          </div>
        </div>
      </div>

      <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06]">
        <h3 className="font-bold text-base mb-4">Payment method</h3>
        <div className="flex items-center gap-4">
          <div className="text-sm text-white/60">
            Securely manage your payment methods and view past invoices through Stripe.
          </div>
          <button 
            onClick={() => portalMut.mutate()}
            disabled={portalMut.isPending}
            className="ml-auto px-4 py-2 border border-white/10 rounded-lg text-sm text-white hover:bg-white/5 transition-colors disabled:opacity-50"
          >
            {portalMut.isPending ? "Loading..." : "Open Billing Portal"}
          </button>
        </div>
      </div>
    </motion.div>
  );
}

