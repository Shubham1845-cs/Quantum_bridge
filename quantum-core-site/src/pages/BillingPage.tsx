import { useParams } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { CreditCard, ExternalLink, Building2 } from "lucide-react";
import { createCheckoutSession, getCustomerPortalUrl } from "../api/billing";
import { useToast } from "../hooks/useToast";
import { PageHeader } from "../components/ui/PageHeader";
import { Card } from "../components/ui/Card";
import Button from "../components/ui/Button";

export default function BillingPage() {
  const { orgId } = useParams<{ orgId: string }>();
  const toast = useToast();

  const checkoutMut = useMutation({
    mutationFn: () => createCheckoutSession(orgId!, "enterprise"),
    onSuccess: (data) => {
      window.location.href = data.url;
    },
    onError: (err: any) => toast.error(`Failed to create checkout session: ${err.message}`),
  });

  const portalMut = useMutation({
    mutationFn: () => getCustomerPortalUrl(orgId!),
    onSuccess: (data) => {
      window.location.href = data.url;
    },
    onError: (err: any) => toast.error(`Failed to access billing portal: ${err.message}`),
  });

  const features = [
    "Unlimited endpoints",
    "99.99% uptime SLA",
    "Dedicated FIPS 140-3 HSM",
    "Priority threat-response support",
  ];

  return (
    <div>
      <PageHeader title="Billing & Usage" description="Manage your Enterprise plan and review usage limits" />

      <div className="mb-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Plan */}
        <Card variant="accent" className="flex flex-col justify-between p-6">
          <div>
            <div className="mb-4 flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-qb-violet/30 bg-qb-violet/10 text-qb-violet">
                  <Building2 size={18} />
                </div>
                <div>
                  <div className="text-lg font-bold">Enterprise Plan</div>
                  <div className="text-xs text-white/40">Custom limits · dedicated HSM</div>
                </div>
              </div>
              <div className="text-right">
                <span className="text-2xl font-bold">$1,200</span>
                <span className="text-sm font-normal text-white/40">/mo</span>
              </div>
            </div>

            <div className="mb-6 space-y-2">
              {features.map((f) => (
                <div key={f} className="flex items-center gap-2 text-sm text-white/70">
                  <span className="text-qb-emerald">✓</span> {f}
                </div>
              ))}
            </div>
          </div>

          <Button onClick={() => checkoutMut.mutate()} variant="primary" disabled={checkoutMut.isPending} className="w-full">
            {checkoutMut.isPending ? "Redirecting…" : "Upgrade to Enterprise"}
          </Button>
        </Card>

        {/* Usage */}
        <Card className="p-6">
          <h3 className="mb-5 text-base font-semibold">Usage this month</h3>

          <div className="mb-6">
            <div className="mb-1 flex justify-between text-sm">
              <span className="text-white/60">Requests</span>
              <span><span className="font-bold">841,200</span> <span className="text-white/40">/ 1,000,000</span></span>
            </div>
            <div className="mb-1 h-2 w-full overflow-hidden rounded-full bg-white/[0.06]">
              <div className="h-full rounded-full bg-gradient-to-r from-qb-cyan to-cyan-300 transition-all duration-500" style={{ width: "84%" }} />
            </div>
            <div className="text-right text-[10px] text-white/40">Resets in 11 days</div>
          </div>

          <div>
            <div className="mb-1 flex justify-between text-sm">
              <span className="text-white/60">Endpoints</span>
              <span><span className="font-bold">2</span> <span className="text-white/40">/ Unlimited</span></span>
            </div>
            <div className="h-2 w-full overflow-hidden rounded-full bg-white/[0.06]">
              <div className="h-full rounded-full bg-qb-violet" style={{ width: "8.33%" }} />
            </div>
          </div>
        </Card>
      </div>

      {/* Payment method */}
      <Card className="p-6">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.03] text-white/70">
            <CreditCard size={18} />
          </div>
          <div className="text-sm text-white/55">
            Securely manage payment methods and view past invoices through Stripe.
          </div>
          <Button
            onClick={() => portalMut.mutate()}
            variant="secondary"
            size="sm"
            disabled={portalMut.isPending}
            className="ml-auto"
          >
            <ExternalLink size={13} className="mr-1.5" />
            {portalMut.isPending ? "Loading…" : "Open Billing Portal"}
          </Button>
        </div>
      </Card>
    </div>
  );
}
