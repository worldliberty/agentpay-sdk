import type * as React from 'react';
import { cn } from '../utils/cn';

export function Label({
  className,
  ...props
}: React.LabelHTMLAttributes<HTMLLabelElement>): React.JSX.Element {
  return <label className={cn('text-sm font-medium leading-none', className)} {...props} />;
}
