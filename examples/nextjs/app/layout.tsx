import type { ReactNode } from 'react';

export const metadata = { title: 'Peerborne Next.js starter' };

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
