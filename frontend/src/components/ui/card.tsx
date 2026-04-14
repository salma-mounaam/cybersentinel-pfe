import React from 'react';

export function Card({ className = '', children }: any) {
  return <div className={`rounded-xl border border-white/10 bg-[#151820] ${className}`}>{children}</div>;
}

export function CardHeader({ className = '', children }: any) {
  return <div className={`p-4 border-b border-white/10 ${className}`}>{children}</div>;
}

export function CardTitle({ className = '', children }: any) {
  return <h3 className={`text-sm font-medium text-white ${className}`}>{children}</h3>;
}

export function CardContent({ className = '', children }: any) {
  return <div className={`p-4 ${className}`}>{children}</div>;
}