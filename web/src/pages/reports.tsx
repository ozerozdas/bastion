import { EmptyState } from '../components/empty-state'
import { buttonVariants } from '../components/ui/button'
import { Link } from '@tanstack/react-router'

export function ReportsPage() {
  return (
    <EmptyState
      title="No security reports yet"
      body="A report appears once a project has been scanned: vulnerabilities, leaked secrets and the fixed version that closes each finding, grouped by package upgrade."
    >
      <Link to="/projects" className={buttonVariants({ variant: 'outline' })}>
        Go to projects
      </Link>
    </EmptyState>
  )
}
