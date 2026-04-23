import React from 'react';

export function Button({
  className = '',
  children,
  variant = 'default',
  size = 'default',
  ...props
}: any) {
  const base = 'inline-flex items-center justify-center rounded-md border text-sm transition';
  const variants: Record<string, string> = {
    default: 'bg-[#1c2030] border-white/10 text-white hover:bg-white/10',
    outline: 'bg-transparent border-white/20 text-white hover:bg-white/10',
    ghost: 'bg-transparent border-transparent text-white hover:bg-white/10',
    secondary: 'bg-white/5 border-white/10 text-white hover:bg-white/10',
  };
  const sizes: Record<string, string> = {
    default: 'h-10 px-4 py-2',
    sm: 'h-8 px-3',
    icon: 'h-8 w-8',
  };

  return (
    <button
      className={`${base} ${variants[variant] || variants.default} ${sizes[size] || sizes.default} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}