import { ref, onMounted } from 'vue';
const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
const menuOpen = ref(false);
const toggleMenu = () => {
    menuOpen.value = !menuOpen.value;
};
onMounted(() => {
    setInterval(() => {
        const menuIcon = document.querySelector('img[alt="Menu"]');
        if (menuIcon) {
            menuIcon.classList.add('rotate-animation');
            setTimeout(() => {
                menuIcon.classList.remove('rotate-animation');
            }, 60000); // 60 seconds
        }
    }, 60000); // 60 seconds
});
const __VLS_fnComponent = (await import('vue')).defineComponent({});
let __VLS_functionalComponentProps;
function __VLS_template() {
    let __VLS_ctx;
    /* Components */
    let __VLS_otherComponents;
    let __VLS_own;
    let __VLS_localComponents;
    let __VLS_components;
    let __VLS_styleScopedClasses;
    // CSS variable injection 
    // CSS variable injection end 
    let __VLS_resolvedLocalAndGlobalComponents;
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("h-screen overflow-hidden relative bg-gradient-to-r from-blue-900 to-blue-700 text-white") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("fixed top-0 left-0 w-full flex items-center p-4 z-10") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("flex items-center ml-4") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("relative z-20") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.button, __VLS_intrinsicElements.button)({ ...{ onClick: (__VLS_ctx.toggleMenu) }, ...{ class: ("focus:outline-none") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.img)({ src: ("@/assets/load-svgrepo-com.svg"), alt: ("Menu"), ...{ class: ("w-8 h-8 transition-transform duration-500") }, ...{ class: (({ 'rotate-180': __VLS_ctx.menuOpen })) }, });
    __VLS_styleScopedClasses = ({ 'rotate-180': menuOpen });
    // @ts-ignore
    [toggleMenu, menuOpen,];
    // @ts-ignore
    const __VLS_0 = {}
        .RouterLink;
    ({}.RouterLink);
    ({}.RouterLink);
    __VLS_components.RouterLink;
    __VLS_components.routerLink;
    __VLS_components.RouterLink;
    __VLS_components.routerLink;
    // @ts-ignore
    [RouterLink, RouterLink,];
    // @ts-ignore
    const __VLS_1 = __VLS_asFunctionalComponent(__VLS_0, new __VLS_0({ to: ("/"), ...{ class: ("text-white font-bold text-xl ml-2") }, }));
    const __VLS_2 = __VLS_1({ to: ("/"), ...{ class: ("text-white font-bold text-xl ml-2") }, }, ...__VLS_functionalComponentArgsRest(__VLS_1));
    ({}({ to: ("/"), ...{ class: ("text-white font-bold text-xl ml-2") }, }));
    (__VLS_5.slots).default;
    const __VLS_5 = __VLS_pickFunctionalComponentCtx(__VLS_0, __VLS_2);
    // @ts-ignore
    const __VLS_6 = {}
        .transition;
    ({}.transition);
    ({}.transition);
    __VLS_components.Transition;
    __VLS_components.transition;
    __VLS_components.Transition;
    __VLS_components.transition;
    // @ts-ignore
    [Transition, Transition,];
    // @ts-ignore
    const __VLS_7 = __VLS_asFunctionalComponent(__VLS_6, new __VLS_6({ name: ("slide-fade"), }));
    const __VLS_8 = __VLS_7({ name: ("slide-fade"), }, ...__VLS_functionalComponentArgsRest(__VLS_7));
    ({}({ name: ("slide-fade"), }));
    if (__VLS_ctx.menuOpen) {
        __VLS_elementAsFunction(__VLS_intrinsicElements.nav, __VLS_intrinsicElements.nav)({ ...{ class: ("fixed top-10 left-10 w-64 bg-black bg-opacity-90 text-white p-4 z-30 rounded-lg shadow-xl") }, });
        __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("flex justify-between items-center mb-8") }, });
        // @ts-ignore
        const __VLS_12 = {}
            .RouterLink;
        ({}.RouterLink);
        ({}.RouterLink);
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        // @ts-ignore
        [RouterLink, RouterLink,];
        // @ts-ignore
        const __VLS_13 = __VLS_asFunctionalComponent(__VLS_12, new __VLS_12({ to: ("/"), ...{ class: ("text-white font-bold text-2xl") }, }));
        const __VLS_14 = __VLS_13({ to: ("/"), ...{ class: ("text-white font-bold text-2xl") }, }, ...__VLS_functionalComponentArgsRest(__VLS_13));
        ({}({ to: ("/"), ...{ class: ("text-white font-bold text-2xl") }, }));
        // @ts-ignore
        [menuOpen,];
        (__VLS_17.slots).default;
        const __VLS_17 = __VLS_pickFunctionalComponentCtx(__VLS_12, __VLS_14);
        __VLS_elementAsFunction(__VLS_intrinsicElements.button, __VLS_intrinsicElements.button)({ ...{ onClick: (__VLS_ctx.toggleMenu) }, ...{ class: ("text-white text-2xl focus:outline-none") }, });
        // @ts-ignore
        [toggleMenu,];
        __VLS_elementAsFunction(__VLS_intrinsicElements.ul, __VLS_intrinsicElements.ul)({});
        __VLS_elementAsFunction(__VLS_intrinsicElements.li, __VLS_intrinsicElements.li)({ ...{ class: ("mb-4") }, });
        // @ts-ignore
        const __VLS_18 = {}
            .RouterLink;
        ({}.RouterLink);
        ({}.RouterLink);
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        // @ts-ignore
        [RouterLink, RouterLink,];
        // @ts-ignore
        const __VLS_19 = __VLS_asFunctionalComponent(__VLS_18, new __VLS_18({ to: ("/"), ...{ class: ("nav-link") }, }));
        const __VLS_20 = __VLS_19({ to: ("/"), ...{ class: ("nav-link") }, }, ...__VLS_functionalComponentArgsRest(__VLS_19));
        ({}({ to: ("/"), ...{ class: ("nav-link") }, }));
        (__VLS_23.slots).default;
        const __VLS_23 = __VLS_pickFunctionalComponentCtx(__VLS_18, __VLS_20);
        __VLS_elementAsFunction(__VLS_intrinsicElements.li, __VLS_intrinsicElements.li)({ ...{ class: ("mb-4") }, });
        // @ts-ignore
        const __VLS_24 = {}
            .RouterLink;
        ({}.RouterLink);
        ({}.RouterLink);
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        // @ts-ignore
        [RouterLink, RouterLink,];
        // @ts-ignore
        const __VLS_25 = __VLS_asFunctionalComponent(__VLS_24, new __VLS_24({ to: ("/console"), ...{ class: ("nav-link") }, }));
        const __VLS_26 = __VLS_25({ to: ("/console"), ...{ class: ("nav-link") }, }, ...__VLS_functionalComponentArgsRest(__VLS_25));
        ({}({ to: ("/console"), ...{ class: ("nav-link") }, }));
        (__VLS_29.slots).default;
        const __VLS_29 = __VLS_pickFunctionalComponentCtx(__VLS_24, __VLS_26);
        __VLS_elementAsFunction(__VLS_intrinsicElements.li, __VLS_intrinsicElements.li)({ ...{ class: ("mb-4") }, });
        // @ts-ignore
        const __VLS_30 = {}
            .RouterLink;
        ({}.RouterLink);
        ({}.RouterLink);
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        // @ts-ignore
        [RouterLink, RouterLink,];
        // @ts-ignore
        const __VLS_31 = __VLS_asFunctionalComponent(__VLS_30, new __VLS_30({ to: ("/port-forward"), ...{ class: ("nav-link") }, }));
        const __VLS_32 = __VLS_31({ to: ("/port-forward"), ...{ class: ("nav-link") }, }, ...__VLS_functionalComponentArgsRest(__VLS_31));
        ({}({ to: ("/port-forward"), ...{ class: ("nav-link") }, }));
        (__VLS_35.slots).default;
        const __VLS_35 = __VLS_pickFunctionalComponentCtx(__VLS_30, __VLS_32);
        __VLS_elementAsFunction(__VLS_intrinsicElements.li, __VLS_intrinsicElements.li)({});
        // @ts-ignore
        const __VLS_36 = {}
            .RouterLink;
        ({}.RouterLink);
        ({}.RouterLink);
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        __VLS_components.RouterLink;
        __VLS_components.routerLink;
        // @ts-ignore
        [RouterLink, RouterLink,];
        // @ts-ignore
        const __VLS_37 = __VLS_asFunctionalComponent(__VLS_36, new __VLS_36({ to: ("/about"), ...{ class: ("nav-link") }, }));
        const __VLS_38 = __VLS_37({ to: ("/about"), ...{ class: ("nav-link") }, }, ...__VLS_functionalComponentArgsRest(__VLS_37));
        ({}({ to: ("/about"), ...{ class: ("nav-link") }, }));
        (__VLS_41.slots).default;
        const __VLS_41 = __VLS_pickFunctionalComponentCtx(__VLS_36, __VLS_38);
    }
    (__VLS_11.slots).default;
    const __VLS_11 = __VLS_pickFunctionalComponentCtx(__VLS_6, __VLS_8);
    // @ts-ignore
    const __VLS_42 = {}
        .RouterView;
    ({}.RouterView);
    ({}.RouterView);
    __VLS_components.RouterView;
    __VLS_components.routerView;
    __VLS_components.RouterView;
    __VLS_components.routerView;
    // @ts-ignore
    [RouterView, RouterView,];
    // @ts-ignore
    const __VLS_43 = __VLS_asFunctionalComponent(__VLS_42, new __VLS_42({}));
    const __VLS_44 = __VLS_43({}, ...__VLS_functionalComponentArgsRest(__VLS_43));
    ({}({}));
    const __VLS_47 = __VLS_pickFunctionalComponentCtx(__VLS_42, __VLS_44);
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['h-screen'];
        __VLS_styleScopedClasses['overflow-hidden'];
        __VLS_styleScopedClasses['relative'];
        __VLS_styleScopedClasses['bg-gradient-to-r'];
        __VLS_styleScopedClasses['from-blue-900'];
        __VLS_styleScopedClasses['to-blue-700'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['fixed'];
        __VLS_styleScopedClasses['top-0'];
        __VLS_styleScopedClasses['left-0'];
        __VLS_styleScopedClasses['w-full'];
        __VLS_styleScopedClasses['flex'];
        __VLS_styleScopedClasses['items-center'];
        __VLS_styleScopedClasses['p-4'];
        __VLS_styleScopedClasses['z-10'];
        __VLS_styleScopedClasses['flex'];
        __VLS_styleScopedClasses['items-center'];
        __VLS_styleScopedClasses['ml-4'];
        __VLS_styleScopedClasses['relative'];
        __VLS_styleScopedClasses['z-20'];
        __VLS_styleScopedClasses['focus:outline-none'];
        __VLS_styleScopedClasses['w-8'];
        __VLS_styleScopedClasses['h-8'];
        __VLS_styleScopedClasses['transition-transform'];
        __VLS_styleScopedClasses['duration-500'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['font-bold'];
        __VLS_styleScopedClasses['text-xl'];
        __VLS_styleScopedClasses['ml-2'];
        __VLS_styleScopedClasses['fixed'];
        __VLS_styleScopedClasses['top-10'];
        __VLS_styleScopedClasses['left-10'];
        __VLS_styleScopedClasses['w-64'];
        __VLS_styleScopedClasses['bg-black'];
        __VLS_styleScopedClasses['bg-opacity-90'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['p-4'];
        __VLS_styleScopedClasses['z-30'];
        __VLS_styleScopedClasses['rounded-lg'];
        __VLS_styleScopedClasses['shadow-xl'];
        __VLS_styleScopedClasses['flex'];
        __VLS_styleScopedClasses['justify-between'];
        __VLS_styleScopedClasses['items-center'];
        __VLS_styleScopedClasses['mb-8'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['font-bold'];
        __VLS_styleScopedClasses['text-2xl'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['text-2xl'];
        __VLS_styleScopedClasses['focus:outline-none'];
        __VLS_styleScopedClasses['mb-4'];
        __VLS_styleScopedClasses['nav-link'];
        __VLS_styleScopedClasses['mb-4'];
        __VLS_styleScopedClasses['nav-link'];
        __VLS_styleScopedClasses['mb-4'];
        __VLS_styleScopedClasses['nav-link'];
        __VLS_styleScopedClasses['nav-link'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                menuOpen: menuOpen,
                toggleMenu: toggleMenu,
            };
        },
    });
}
export default (await import('vue')).defineComponent({
    setup() {
        return {};
    },
});
;
