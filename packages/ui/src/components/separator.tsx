import type * as React from 'react';
import { cn } from '../utils/cn';

export function Separator({
  className,
  ...props
}: React.HTMLAttributes<HTMLHRElement>): React.JSX.Element {
  return <hr className={cn('h-px w-full border-0 bg-border', className)} {...props} />;
}
