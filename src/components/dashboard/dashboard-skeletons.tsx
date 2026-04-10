import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";

export function OverviewSkeleton() {
  return (
    <div className="grid gap-6 md:grid-cols-3">
      <Skeleton className="h-40 w-full rounded-3xl" />
      <Skeleton className="h-40 w-full rounded-3xl" />
      <Skeleton className="h-40 w-full rounded-3xl" />
    </div>
  );
}

export function ChartsSkeleton() {
  return (
    <div className="grid gap-6 grid-cols-1 lg:grid-cols-12">
      <div className="lg:col-span-4">
        <Card className="glass-card premium-card rounded-3xl overflow-hidden h-full border-none shadow-lg">
          <CardHeader className="pb-0">
            <Skeleton className="h-6 w-32 mb-1" />
            <Skeleton className="h-4 w-48" />
          </CardHeader>
          <div className="p-6 flex items-center justify-center">
            <Skeleton className="h-[250px] w-[250px] rounded-full" />
          </div>
        </Card>
      </div>
      <div className="lg:col-span-8">
        <Card className="glass-card premium-card rounded-3xl overflow-hidden h-full border-none shadow-lg">
          <CardHeader className="pb-0">
            <Skeleton className="h-6 w-32 mb-1" />
            <Skeleton className="h-4 w-48" />
          </CardHeader>
          <div className="p-6">
            <Skeleton className="h-[250px] w-full rounded-xl" />
          </div>
        </Card>
      </div>
    </div>
  );
}

export function SavingGoalsSkeleton() {
  return (
    <Card className="glass-card premium-card rounded-3xl h-full border-none shadow-lg">
      <CardHeader>
        <Skeleton className="h-6 w-40 mb-1" />
        <Skeleton className="h-4 w-56" />
      </CardHeader>
      <CardContent className="space-y-6">
        {[1, 2, 3].map((i) => (
          <div key={i} className="space-y-2">
            <div className="flex items-center justify-between">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-4 w-10" />
            </div>
            <Skeleton className="h-3 w-full rounded-full" />
            <div className="flex justify-between">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-3 w-24" />
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

export function WalletListSkeleton() {
  return (
    <Card className="glass-card premium-card rounded-3xl border-none shadow-lg">
      <CardHeader className="flex flex-row items-center justify-between">
        <div className="space-y-1">
          <Skeleton className="h-5 w-24" />
          <Skeleton className="h-3 w-32" />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="flex items-center p-3">
            <Skeleton className="h-12 w-12 rounded-2xl" />
            <div className="ml-4 flex-1 space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-3 w-16" />
            </div>
            <Skeleton className="h-5 w-20" />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
