import type {Metadata} from 'next';
import { Cinzel_Decorative, Space_Grotesk, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const cinzelDecorative = Cinzel_Decorative({
  subsets: ['latin'],
  weight: ['700'],
  variable: '--font-display',
});

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-sans',
});

const jetbrains = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'Rakshak — AI Cyber Threat Hunter & SIEM',
  description: 'Always Watching, Always Protecting. Real-time security monitoring, Wazuh-pattern log analysis, UEBA anomaly detection, MITRE ATT&CK mapping, and explainable AI threat investigation.',
  openGraph: {
    title: 'Rakshak — AI Cyber Threat Hunter & SIEM',
    description: 'Always Watching, Always Protecting. Real-time security monitoring, Wazuh-pattern log analysis, UEBA anomaly detection, MITRE ATT&CK mapping, and explainable AI threat investigation.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Rakshak — AI Cyber Threat Hunter & SIEM',
    description: 'Always Watching, Always Protecting. Real-time security monitoring, Wazuh-pattern log analysis, UEBA anomaly detection, MITRE ATT&CK mapping, and explainable AI threat investigation.',
  },
};

export default function RootLayout({children}: {children: React.ReactNode}) {
  return (
    <html lang="en" className={`${cinzelDecorative.variable} ${spaceGrotesk.variable} ${jetbrains.variable} dark`}>
      <body suppressHydrationWarning className="bg-[#07090F] text-slate-100 antialiased selection:bg-amber-500/30 selection:text-amber-200 font-sans">
        {children}
      </body>
    </html>
  );
}
