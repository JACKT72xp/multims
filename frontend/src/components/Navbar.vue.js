import { ref } from 'vue';
import { RouterLink } from 'vue-router';
const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
const isOpen = ref(false);
const toggleMenu = () => {
    isOpen.value = !isOpen.value;
};
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
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({});
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ((['fixed top-0 left-0 h-full z-50 transition-transform duration-300', __VLS_ctx.isOpen ? 'translate-x-0' : '-translate-x-full'])) }, });
    __VLS_styleScopedClasses = (['fixed top-0 left-0 h-full z-50 transition-transform duration-300', isOpen ? 'translate-x-0' : '-translate-x-full']);
    __VLS_elementAsFunction(__VLS_intrinsicElements.nav, __VLS_intrinsicElements.nav)({ ...{ class: ("bg-dark p-6 w-64 shadow-lg") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("flex items-center justify-between mb-6") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("text-white font-bold text-2xl") }, });
    // @ts-ignore
    [isOpen,];
    __VLS_elementAsFunction(__VLS_intrinsicElements.button, __VLS_intrinsicElements.button)({ ...{ onClick: (__VLS_ctx.toggleMenu) }, ...{ class: ("text-white") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.svg, __VLS_intrinsicElements.svg)({ xmlns: ("http://www.w3.org/2000/svg"), fill: ("none"), viewBox: ("0 0 24 24"), stroke: ("currentColor"), ...{ class: ("w-6 h-6") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.path)({ "stroke-linecap": ("round"), "stroke-linejoin": ("round"), "stroke-width": ("2"), d: ("M6 18L18 6M6 6l12 12"), });
    // @ts-ignore
    [toggleMenu,];
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({});
    // @ts-ignore
    const __VLS_0 = {}
        .RouterLink;
    ({}.RouterLink);
    ({}.RouterLink);
    __VLS_components.RouterLink;
    __VLS_components.RouterLink;
    // @ts-ignore
    [RouterLink, RouterLink,];
    // @ts-ignore
    const __VLS_1 = __VLS_asFunctionalComponent(__VLS_0, new __VLS_0({ ...{ 'onClick': {} }, to: ("/"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }));
    const __VLS_2 = __VLS_1({ ...{ 'onClick': {} }, to: ("/"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }, ...__VLS_functionalComponentArgsRest(__VLS_1));
    ({}({ ...{ 'onClick': {} }, to: ("/"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }));
    let __VLS_6;
    const __VLS_7 = {
        onClick: (__VLS_ctx.toggleMenu)
    };
    // @ts-ignore
    [toggleMenu,];
    (__VLS_5.slots).default;
    const __VLS_5 = __VLS_pickFunctionalComponentCtx(__VLS_0, __VLS_2);
    let __VLS_3;
    let __VLS_4;
    // @ts-ignore
    const __VLS_8 = {}
        .RouterLink;
    ({}.RouterLink);
    ({}.RouterLink);
    __VLS_components.RouterLink;
    __VLS_components.RouterLink;
    // @ts-ignore
    [RouterLink, RouterLink,];
    // @ts-ignore
    const __VLS_9 = __VLS_asFunctionalComponent(__VLS_8, new __VLS_8({ ...{ 'onClick': {} }, to: ("/console"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }));
    const __VLS_10 = __VLS_9({ ...{ 'onClick': {} }, to: ("/console"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }, ...__VLS_functionalComponentArgsRest(__VLS_9));
    ({}({ ...{ 'onClick': {} }, to: ("/console"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }));
    let __VLS_14;
    const __VLS_15 = {
        onClick: (__VLS_ctx.toggleMenu)
    };
    // @ts-ignore
    [toggleMenu,];
    (__VLS_13.slots).default;
    const __VLS_13 = __VLS_pickFunctionalComponentCtx(__VLS_8, __VLS_10);
    let __VLS_11;
    let __VLS_12;
    // @ts-ignore
    const __VLS_16 = {}
        .RouterLink;
    ({}.RouterLink);
    ({}.RouterLink);
    __VLS_components.RouterLink;
    __VLS_components.RouterLink;
    // @ts-ignore
    [RouterLink, RouterLink,];
    // @ts-ignore
    const __VLS_17 = __VLS_asFunctionalComponent(__VLS_16, new __VLS_16({ ...{ 'onClick': {} }, to: ("/port-forward"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }));
    const __VLS_18 = __VLS_17({ ...{ 'onClick': {} }, to: ("/port-forward"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }, ...__VLS_functionalComponentArgsRest(__VLS_17));
    ({}({ ...{ 'onClick': {} }, to: ("/port-forward"), ...{ class: ("nav-link block text-light mb-4 hover:text-primary") }, }));
    let __VLS_22;
    const __VLS_23 = {
        onClick: (__VLS_ctx.toggleMenu)
    };
    // @ts-ignore
    [toggleMenu,];
    (__VLS_21.slots).default;
    const __VLS_21 = __VLS_pickFunctionalComponentCtx(__VLS_16, __VLS_18);
    let __VLS_19;
    let __VLS_20;
    // @ts-ignore
    const __VLS_24 = {}
        .RouterLink;
    ({}.RouterLink);
    ({}.RouterLink);
    __VLS_components.RouterLink;
    __VLS_components.RouterLink;
    // @ts-ignore
    [RouterLink, RouterLink,];
    // @ts-ignore
    const __VLS_25 = __VLS_asFunctionalComponent(__VLS_24, new __VLS_24({ ...{ 'onClick': {} }, to: ("/about"), ...{ class: ("nav-link block text-light hover:text-primary") }, }));
    const __VLS_26 = __VLS_25({ ...{ 'onClick': {} }, to: ("/about"), ...{ class: ("nav-link block text-light hover:text-primary") }, }, ...__VLS_functionalComponentArgsRest(__VLS_25));
    ({}({ ...{ 'onClick': {} }, to: ("/about"), ...{ class: ("nav-link block text-light hover:text-primary") }, }));
    let __VLS_30;
    const __VLS_31 = {
        onClick: (__VLS_ctx.toggleMenu)
    };
    // @ts-ignore
    [toggleMenu,];
    (__VLS_29.slots).default;
    const __VLS_29 = __VLS_pickFunctionalComponentCtx(__VLS_24, __VLS_26);
    let __VLS_27;
    let __VLS_28;
    __VLS_elementAsFunction(__VLS_intrinsicElements.button, __VLS_intrinsicElements.button)({ ...{ onClick: (__VLS_ctx.toggleMenu) }, ...{ class: ("fixed top-6 left-6 z-50 p-2 bg-primary text-white rounded-full shadow-lg hover:bg-opacity-80") }, ...{ style: ({}) }, });
    if (!__VLS_ctx.isOpen) {
        __VLS_elementAsFunction(__VLS_intrinsicElements.svg, __VLS_intrinsicElements.svg)({ xmlns: ("http://www.w3.org/2000/svg"), fill: ("none"), viewBox: ("0 0 24 24"), stroke: ("currentColor"), ...{ class: ("w-6 h-6") }, });
        __VLS_elementAsFunction(__VLS_intrinsicElements.path)({ "stroke-linecap": ("round"), "stroke-linejoin": ("round"), "stroke-width": ("2"), d: ("M4 6h16M4 12h16m-7 6h7"), });
        // @ts-ignore
        [isOpen, toggleMenu,];
    }
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['bg-dark'];
        __VLS_styleScopedClasses['p-6'];
        __VLS_styleScopedClasses['w-64'];
        __VLS_styleScopedClasses['shadow-lg'];
        __VLS_styleScopedClasses['flex'];
        __VLS_styleScopedClasses['items-center'];
        __VLS_styleScopedClasses['justify-between'];
        __VLS_styleScopedClasses['mb-6'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['font-bold'];
        __VLS_styleScopedClasses['text-2xl'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['w-6'];
        __VLS_styleScopedClasses['h-6'];
        __VLS_styleScopedClasses['nav-link'];
        __VLS_styleScopedClasses['block'];
        __VLS_styleScopedClasses['text-light'];
        __VLS_styleScopedClasses['mb-4'];
        __VLS_styleScopedClasses['hover:text-primary'];
        __VLS_styleScopedClasses['nav-link'];
        __VLS_styleScopedClasses['block'];
        __VLS_styleScopedClasses['text-light'];
        __VLS_styleScopedClasses['mb-4'];
        __VLS_styleScopedClasses['hover:text-primary'];
        __VLS_styleScopedClasses['nav-link'];
        __VLS_styleScopedClasses['block'];
        __VLS_styleScopedClasses['text-light'];
        __VLS_styleScopedClasses['mb-4'];
        __VLS_styleScopedClasses['hover:text-primary'];
        __VLS_styleScopedClasses['nav-link'];
        __VLS_styleScopedClasses['block'];
        __VLS_styleScopedClasses['text-light'];
        __VLS_styleScopedClasses['hover:text-primary'];
        __VLS_styleScopedClasses['fixed'];
        __VLS_styleScopedClasses['top-6'];
        __VLS_styleScopedClasses['left-6'];
        __VLS_styleScopedClasses['z-50'];
        __VLS_styleScopedClasses['p-2'];
        __VLS_styleScopedClasses['bg-primary'];
        __VLS_styleScopedClasses['text-white'];
        __VLS_styleScopedClasses['rounded-full'];
        __VLS_styleScopedClasses['shadow-lg'];
        __VLS_styleScopedClasses['hover:bg-opacity-80'];
        __VLS_styleScopedClasses['w-6'];
        __VLS_styleScopedClasses['h-6'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                RouterLink: RouterLink,
                isOpen: isOpen,
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
