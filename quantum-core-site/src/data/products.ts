export interface Product {
  id: string;
  name: string;
  subName: string;
  price: string;
  description: string;
  folderPath: string;
  themeColor: string;
  gradient: string;
  features: string[];
  stats: { label: string; val: string }[];
  section1: { title: string; subtitle: string };
  section2: { title: string; subtitle: string };
  section3: { title: string; subtitle: string };
  section4: { title: string; subtitle: string };
  detailsSection: { title: string; description: string; imageAlt: string };
  techSection: { title: string; description: string };
  buyNowSection: {
    price: string;
    unit: string;
    specs: string[];
    deliveryPromise: string;
    warranty: string;
  };
}

export const products: Product[] = [
  {
    id: "quantum-core",
    name: "Quantum Core",
    subName: "Data, illuminated.",
    price: "$1,299",
    description: "Zero Latency - Photonic Transmission - Absolute Security",
    folderPath: "/images/frames",
    themeColor: "#00FFFF",
    gradient: "linear-gradient(135deg, #00FFFF 0%, #8A2BE2 100%)",
    features: ["Photonic Routing", "Zero Latency", "Quantum Encrypted"],
    stats: [
      { label: "Speed", val: "100 Tbps" },
      { label: "Latency", val: "0.1ms" },
      { label: "Loss", val: "0%" },
    ],
    section1: {
      title: "The Void.",
      subtitle: "A universe of raw data waiting to be harnessed.",
    },
    section2: {
      title: "Igniting the Stream.",
      subtitle:
        "Our proprietary plasma conduit stabilizes the quantum flow.",
    },
    section3: {
      title: "Hyper-Speed Transmission.",
      subtitle:
        "Cyan and violet photons intertwine to carry data faster than light.",
    },
    section4: {
      title: "Welcome to the Future of Networking.",
      subtitle: "",
    },
    detailsSection: {
      title: "Engineered for the Impossible",
      description:
        "The Quantum Core represents a paradigm shift in data transmission. By encapsulating photonic streams in a zero-gravity vacuum cylinder, data is immune to physical interference. It's not just a cable; it's an isolated universe for your network.",
      imageAlt: "Quantum Core Details",
    },
    techSection: {
      title: "Ethereal Shielding",
      description:
        "The outer shell is reinforced with a translucent carbon-glass matrix, providing military-grade durability while allowing you to monitor the physical manifestation of your data streams in real-time.",
    },
    buyNowSection: {
      price: "$1,299",
      unit: "per 10-meter node",
      specs: ["Vacuum Sealed", "Self-Cooling", "AI Monitored"],
      deliveryPromise:
        "Dispatched via secure, shock-proof transport globally.",
      warranty: "Lifetime structural integrity guarantee.",
    },
  },
];
