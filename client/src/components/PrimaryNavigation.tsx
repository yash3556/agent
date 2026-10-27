import { useEffect, useRef, type ReactNode } from "react";

type NavigationItem<PageId extends string> = {
  id: PageId;
  label: string;
  glyph: ReactNode;
};

type PrimaryNavigationProps<PageId extends string> = {
  items: NavigationItem<PageId>[];
  activePage: PageId;
  pendingCount: number | null;
  onNavigate: (page: PageId) => void;
};

export function PrimaryNavigation<PageId extends string>({
  items,
  activePage,
  pendingCount,
  onNavigate,
}: PrimaryNavigationProps<PageId>) {
  const navigationRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const navigation = navigationRef.current;
    const activeItem = navigation?.querySelector<HTMLElement>('[aria-current="page"]');
    if (!navigation || !activeItem) return;

    const navigationBounds = navigation.getBoundingClientRect();
    const itemBounds = activeItem.getBoundingClientRect();
    const offset = itemBounds.left < navigationBounds.left
      ? itemBounds.left - navigationBounds.left
      : itemBounds.right > navigationBounds.right
        ? itemBounds.right - navigationBounds.right
        : 0;
    if (offset) {
      navigation.scrollBy({
        left: offset,
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      });
    }
  }, [activePage]);

  return (
    <nav ref={navigationRef} aria-label="Main navigation">
      {items.map((item) => (
        <button
          key={item.id}
          type="button"
          title={item.label}
          aria-label={item.label}
          className={`nav-item ${activePage === item.id ? "active" : ""}`}
          onClick={() => onNavigate(item.id)}
          aria-current={activePage === item.id ? "page" : undefined}
        >
          <span className="icon" aria-hidden="true">{item.glyph}</span>
          <span>{item.label}</span>
          {item.id === "approvals" && pendingCount !== null && pendingCount > 0 && (
            <span className="nav-count">{pendingCount}</span>
          )}
        </button>
      ))}
    </nav>
  );
}
