'use client';

import { useEffect } from "react";
import { usePathname, useSearchParams } from "next/navigation";

const ScrollToTop = () => {
    const pathname = usePathname();
    const searchParams = useSearchParams();

    useEffect(() => {
        window.scrollTo({
            top: 0,
            left: 0,
            behavior: "auto",
        });
    }, [pathname, searchParams]);

    return null;
};

export default ScrollToTop;
