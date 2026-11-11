import { EmptyState } from '../components/empty-state'
import { buttonVariants } from '../components/ui/button'
import { Link } from '@tanstack/react-router'

export function HistoryPage() {
  return (
    <EmptyState
      title="No scans yet"
      body="Each scan is saved here so you can open two of them side by side and see what is new, fixed or still open."
    >
      <Link to="/projects" className={buttonVariants({ variant: 'outline' })}>
        Go to projects
      </Link>
    </EmptyState>
  )
}
