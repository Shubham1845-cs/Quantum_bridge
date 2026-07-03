import { useState } from "react";
import { motion } from "framer-motion";
import { Mail, Phone, Send } from "lucide-react";

export default function HelpContactSection() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    message: "",
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitStatus, setSubmitStatus] = useState<"idle" | "success" | "error">("idle");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    
    // Simulate form submission
    setTimeout(() => {
      setIsSubmitting(false);
      setSubmitStatus("success");
      setFormData({ name: "", email: "", message: "" });
      
      // Reset success message after 3 seconds
      setTimeout(() => setSubmitStatus("idle"), 3000);
    }, 1000);
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  return (
    <section
      id="help"
      className="relative py-24 sm:py-32 overflow-hidden"
      style={{
        background: "linear-gradient(180deg, rgba(0,0,0,0.8) 0%, rgba(10,5,20,0.95) 50%, transparent 100%)",
      }}
    >
      {/* Ambient particles */}
      <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
        {Array.from({ length: 12 }).map((_, i) => (
          <motion.span
            key={i}
            className="absolute rounded-full"
            style={{
              left: `${(i * 67) % 100}%`,
              top: `${(i * 43) % 100}%`,
              width: i % 3 === 0 ? 3 : 2,
              height: i % 3 === 0 ? 3 : 2,
              background: i % 2 === 0 ? "#c084fc" : "#67e8f9",
              boxShadow: `0 0 12px ${i % 2 === 0 ? "#c084fc" : "#67e8f9"}`,
              opacity: 0.4,
            }}
            animate={{ y: [0, -20, 0], opacity: [0.2, 0.6, 0.2] }}
            transition={{ duration: 5 + (i % 4), repeat: Infinity, delay: i * 0.4, ease: "easeInOut" }}
          />
        ))}
      </div>

      <div className="relative z-10 mx-auto max-w-[1280px] px-5 sm:px-8">
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: "-100px" }}
          transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
        >
          {/* Section header */}
          <div className="text-center mb-16">
            <motion.span
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.1, duration: 0.6 }}
              className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium tracking-wider uppercase mb-6"
              style={{
                borderColor: "rgba(192,132,252,0.35)",
                color: "#c084fc",
                background: "rgba(192,132,252,0.06)",
              }}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: "#c084fc", boxShadow: "0 0 10px #c084fc" }} />
              Support
            </motion.span>

            <h2
              style={{
                fontFamily: "var(--font-heading)",
                fontSize: "clamp(1.8rem, 4.5vw, 3rem)",
                lineHeight: 1.05,
                letterSpacing: "-0.01em",
                color: "#FFFFFF",
                marginBottom: 20,
              }}
            >
              Get Help & Support
            </h2>
            <p
              style={{
                color: "rgba(255,255,255,0.75)",
                fontSize: "clamp(0.95rem, 1.6vw, 1.05rem)",
                lineHeight: 1.7,
                maxWidth: 720,
                margin: "0 auto",
              }}
            >
              Have questions? We're here to help you get started with QuantumBridge
            </p>
          </div>

          {/* Content Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 max-w-6xl mx-auto">
            {/* Contact Information */}
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.2, duration: 0.6 }}
              className="space-y-8"
            >
              <div>
                <h3
                  className="text-2xl font-semibold mb-6"
                  style={{ fontFamily: "var(--font-heading)", color: "#FFFFFF" }}
                >
                  Contact Information
                </h3>
                <div className="space-y-6">
                  {/* Email */}
                  <div
                    className="flex items-start gap-4 p-4 rounded-lg transition-all hover:scale-[1.02]"
                    style={{
                      background: "rgba(255,255,255,0.03)",
                      backdropFilter: "blur(10px)",
                      border: "1px solid rgba(255,255,255,0.08)",
                    }}
                  >
                    <div
                      className="p-3 rounded-lg"
                      style={{
                        background: "rgba(103,232,249,0.1)",
                        border: "1px solid rgba(103,232,249,0.2)",
                      }}
                    >
                      <Mail size={20} style={{ color: "#67e8f9" }} />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-white/50 mb-1">Email</div>
                      <a
                        href="mailto:gaikwadshubham62173@gmail.com"
                        className="text-base font-medium hover:text-cyan-400 transition-colors"
                        style={{ color: "#67e8f9" }}
                      >
                        gaikwadshubham62173@gmail.com
                      </a>
                    </div>
                  </div>

                  {/* Phone */}
                  <div
                    className="flex items-start gap-4 p-4 rounded-lg transition-all hover:scale-[1.02]"
                    style={{
                      background: "rgba(255,255,255,0.03)",
                      backdropFilter: "blur(10px)",
                      border: "1px solid rgba(255,255,255,0.08)",
                    }}
                  >
                    <div
                      className="p-3 rounded-lg"
                      style={{
                        background: "rgba(192,132,252,0.1)",
                        border: "1px solid rgba(192,132,252,0.2)",
                      }}
                    >
                      <Phone size={20} style={{ color: "#c084fc" }} />
                    </div>
                    <div>
                      <div className="text-sm font-medium text-white/50 mb-1">Phone</div>
                      <a
                        href="tel:+917499766945"
                        className="text-base font-medium hover:text-purple-400 transition-colors"
                        style={{ color: "#c084fc" }}
                      >
                        +91 7499766945
                      </a>
                    </div>
                  </div>
                </div>
              </div>

              {/* Additional Info */}
              <div
                className="p-6 rounded-lg"
                style={{
                  background: "rgba(103,232,249,0.05)",
                  border: "1px solid rgba(103,232,249,0.15)",
                }}
              >
                <h4 className="text-lg font-semibold mb-3" style={{ color: "#67e8f9" }}>
                  Response Time
                </h4>
                <p className="text-sm text-white/70 leading-relaxed">
                  Our support team typically responds within 24 hours during business days.
                  For urgent security matters, please mark your message as "Urgent" in the subject line.
                </p>
              </div>
            </motion.div>

            {/* Contact Form */}
            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ delay: 0.3, duration: 0.6 }}
            >
              <div
                className="p-8 rounded-xl"
                style={{
                  background: "rgba(255,255,255,0.03)",
                  backdropFilter: "blur(20px)",
                  border: "1px solid rgba(255,255,255,0.1)",
                  boxShadow: "0 8px 32px rgba(0,0,0,0.3)",
                }}
              >
                <h3
                  className="text-2xl font-semibold mb-6"
                  style={{ fontFamily: "var(--font-heading)", color: "#FFFFFF" }}
                >
                  Send us a message
                </h3>

                <form onSubmit={handleSubmit} className="space-y-5">
                  {/* Name Input */}
                  <div>
                    <label htmlFor="name" className="block text-sm font-medium text-white/70 mb-2">
                      Name
                    </label>
                    <input
                      type="text"
                      id="name"
                      name="name"
                      value={formData.name}
                      onChange={handleChange}
                      required
                      className="w-full px-4 py-3 rounded-lg text-white placeholder-white/40 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-400/50"
                      style={{
                        background: "rgba(255,255,255,0.05)",
                        border: "1px solid rgba(255,255,255,0.1)",
                        backdropFilter: "blur(10px)",
                      }}
                      placeholder="Your name"
                    />
                  </div>

                  {/* Email Input */}
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-white/70 mb-2">
                      Email
                    </label>
                    <input
                      type="email"
                      id="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      required
                      className="w-full px-4 py-3 rounded-lg text-white placeholder-white/40 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-400/50"
                      style={{
                        background: "rgba(255,255,255,0.05)",
                        border: "1px solid rgba(255,255,255,0.1)",
                        backdropFilter: "blur(10px)",
                      }}
                      placeholder="your.email@example.com"
                    />
                  </div>

                  {/* Message Textarea */}
                  <div>
                    <label htmlFor="message" className="block text-sm font-medium text-white/70 mb-2">
                      Message
                    </label>
                    <textarea
                      id="message"
                      name="message"
                      value={formData.message}
                      onChange={handleChange}
                      required
                      rows={5}
                      className="w-full px-4 py-3 rounded-lg text-white placeholder-white/40 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-400/50 resize-none"
                      style={{
                        background: "rgba(255,255,255,0.05)",
                        border: "1px solid rgba(255,255,255,0.1)",
                        backdropFilter: "blur(10px)",
                      }}
                      placeholder="How can we help you?"
                    />
                  </div>

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full relative group overflow-hidden rounded-lg px-6 py-3.5 text-white font-semibold transition-all hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                    style={{
                      background: "linear-gradient(135deg, rgba(103,232,249,0.2) 0%, rgba(192,132,252,0.2) 100%)",
                      border: "1px solid rgba(103,232,249,0.3)",
                      boxShadow: "0 4px 16px rgba(103,232,249,0.2)",
                    }}
                  >
                    <span className="relative z-10 flex items-center gap-2">
                      {isSubmitting ? "Sending..." : "Send Message"}
                      <Send size={18} />
                    </span>
                    <div
                      className="absolute inset-0 opacity-0 group-hover:opacity-100 transition duration-300"
                      style={{
                        background: "linear-gradient(135deg, rgba(103,232,249,0.3) 0%, rgba(192,132,252,0.3) 100%)",
                      }}
                    />
                  </button>

                  {/* Success Message */}
                  {submitStatus === "success" && (
                    <motion.div
                      initial={{ opacity: 0, y: -10 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="p-4 rounded-lg text-center"
                      style={{
                        background: "rgba(103,232,249,0.1)",
                        border: "1px solid rgba(103,232,249,0.3)",
                      }}
                    >
                      <p className="text-sm font-medium" style={{ color: "#67e8f9" }}>
                        ✓ Message sent successfully! We'll get back to you soon.
                      </p>
                    </motion.div>
                  )}
                </form>
              </div>
            </motion.div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
