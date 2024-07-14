import { ref } from 'vue';
import LoadKubeConfig from '../components/LoadKubeConfig.vue';
import SelectCluster from '../components/SelectCluster.vue';
import PortForwardForm from '../components/PortForwardForm.vue';
const { defineProps, defineSlots, defineEmits, defineExpose, defineModel, defineOptions, withDefaults, } = await import('vue');
const step = ref(1);
const nextStep = () => {
    step.value++;
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
    __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({ ...{ class: ("port-forward-setup") }, });
    __VLS_elementAsFunction(__VLS_intrinsicElements.h1, __VLS_intrinsicElements.h1)({});
    if (__VLS_ctx.step === 1) {
        __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({});
        // @ts-ignore
        [LoadKubeConfig,];
        // @ts-ignore
        const __VLS_0 = __VLS_asFunctionalComponent(LoadKubeConfig, new LoadKubeConfig({ ...{ 'onLoaded': {} }, }));
        const __VLS_1 = __VLS_0({ ...{ 'onLoaded': {} }, }, ...__VLS_functionalComponentArgsRest(__VLS_0));
        ({}({ ...{ 'onLoaded': {} }, }));
        let __VLS_5;
        const __VLS_6 = {
            onLoaded: (__VLS_ctx.nextStep)
        };
        // @ts-ignore
        [step, nextStep,];
        const __VLS_4 = __VLS_pickFunctionalComponentCtx(LoadKubeConfig, __VLS_1);
        let __VLS_2;
        let __VLS_3;
    }
    else if (__VLS_ctx.step === 2) {
        __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({});
        // @ts-ignore
        [SelectCluster,];
        // @ts-ignore
        const __VLS_7 = __VLS_asFunctionalComponent(SelectCluster, new SelectCluster({ ...{ 'onSelected': {} }, }));
        const __VLS_8 = __VLS_7({ ...{ 'onSelected': {} }, }, ...__VLS_functionalComponentArgsRest(__VLS_7));
        ({}({ ...{ 'onSelected': {} }, }));
        let __VLS_12;
        const __VLS_13 = {
            onSelected: (__VLS_ctx.nextStep)
        };
        // @ts-ignore
        [step, nextStep,];
        const __VLS_11 = __VLS_pickFunctionalComponentCtx(SelectCluster, __VLS_8);
        let __VLS_9;
        let __VLS_10;
    }
    else if (__VLS_ctx.step === 3) {
        __VLS_elementAsFunction(__VLS_intrinsicElements.div, __VLS_intrinsicElements.div)({});
        // @ts-ignore
        [PortForwardForm,];
        // @ts-ignore
        const __VLS_14 = __VLS_asFunctionalComponent(PortForwardForm, new PortForwardForm({}));
        const __VLS_15 = __VLS_14({}, ...__VLS_functionalComponentArgsRest(__VLS_14));
        ({}({}));
        // @ts-ignore
        [step,];
        const __VLS_18 = __VLS_pickFunctionalComponentCtx(PortForwardForm, __VLS_15);
    }
    if (typeof __VLS_styleScopedClasses === 'object' && !Array.isArray(__VLS_styleScopedClasses)) {
        __VLS_styleScopedClasses['port-forward-setup'];
    }
    var __VLS_slots;
    return __VLS_slots;
    const __VLS_componentsOption = {};
    let __VLS_name;
    let __VLS_defineComponent;
    const __VLS_internalComponent = __VLS_defineComponent({
        setup() {
            return {
                LoadKubeConfig: LoadKubeConfig,
                SelectCluster: SelectCluster,
                PortForwardForm: PortForwardForm,
                step: step,
                nextStep: nextStep,
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
