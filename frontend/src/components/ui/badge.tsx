import React from 'react';

export function Badge({ className = '', children, variant = 'default' }: any) {
  const variants: Record<string, string> = {
    default: 'bg-white/10 text-white border-white/10',
    secondary: 'bg-white/5 text-white border-white/10',
    outline: 'bg-transparent text-white border-white/20',
  };

  return (
    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs ${variants[variant] || variants.default} ${className}`}>
      {children}
    </span>
  );
}